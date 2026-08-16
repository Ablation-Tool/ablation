#!/usr/bin/env python3
"""
hijoy_ptt_re.py — HiJoy PTT Protocol Reverse Engineering Tool

Analyzes libhijoyptt.so from HiJoy iWalkie Android APKs to extract:
  - JNI function entry points
  - Protocol constants and network I/O patterns
  - Default server configuration (IP/port)
  - Hardcoded credentials (appkey, Agora App ID)

Target: com.hijoytech.iwalkie* APKs (PTT/walkie-talkie apps)
Base: WebRTC VoiceEngine fork with proprietary signaling on port 5000

Architecture
────────────
1. ELF symbol extraction (libhijoyptt.so JNI surface)
2. String extraction (server IPs, ports, protocol markers)
3. Credential harvesting from DEX (appkey, Agora App ID)
4. Protocol constant enumeration (message types, opcodes)

Usage:
  python3 hijoy_ptt_re.py --apk /path/to/wecom.apk
  python3 hijoy_ptt_re.py --lib /path/to/libhijoyptt.so --dex /path/to/classes.dex

Output:
  JSON report with:
    - JNI function table
    - Protocol constants
    - Server infrastructure
    - Extracted credentials

Paper basis:
  - "Binary-Level Protocol Reverse Engineering" (AutoFormat, Netzob, DiscovRE)
  - "Toward Automated Protocol Reverse Engineering" (Antunes et al.)
  - JNI reverse engineering: "Analyzing Android's Native Code" (Bao et al.)

Author: NuClide Research (2026-08-16)
License: Internal research use only
"""

import argparse
import json
import re
import struct
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import tempfile
import zipfile

class HiJoyPTTRE:
    """HiJoy PTT protocol reverse engineering analyzer"""

    JNI_FUNCTIONS = [
        'Java_com_hijoytech_ptt_lib_LopJni_CreateChannel',
        'Java_com_hijoytech_ptt_lib_LopJni_DeleteChannel',
        'Java_com_hijoytech_ptt_lib_LopJni_SetLocalReceiver',
        'Java_com_hijoytech_ptt_lib_LopJni_SetSendDestination',
        'Java_com_hijoytech_ptt_lib_LopJni_StartSend',
        'Java_com_hijoytech_ptt_lib_LopJni_StopSend',
        'Java_com_hijoytech_ptt_lib_LopJni_SetSendCodec',
        'Java_com_hijoytech_ptt_lib_LopJni_SendSignaling',
        'Java_com_hijoytech_ptt_lib_LopJni_StartListen',
        'Java_com_hijoytech_ptt_lib_LopJni_StopListen',
    ]

    PROTOCOL_PORTS = [5000, 1000, 32000, 601, 8000]

    def __init__(self, lib_path: Optional[Path] = None, dex_path: Optional[Path] = None, apk_path: Optional[Path] = None):
        self.lib_path = lib_path
        self.dex_path = dex_path
        self.apk_path = apk_path
        self.temp_dir = None

        if apk_path:
            self._extract_apk()

    def _extract_apk(self):
        """Extract APK to temp directory"""
        self.temp_dir = tempfile.mkdtemp(prefix='hijoy_ptt_')
        temp_path = Path(self.temp_dir)

        with zipfile.ZipFile(self.apk_path, 'r') as zf:
            zf.extractall(temp_path)

        # Locate lib and dex
        lib_candidates = list(temp_path.glob('lib/armeabi-v7a/libhijoyptt.so')) + \
                        list(temp_path.glob('lib/arm64-v8a/libhijoyptt.so'))
        if lib_candidates:
            self.lib_path = lib_candidates[0]

        dex_candidates = list(temp_path.glob('classes.dex'))
        if dex_candidates:
            self.dex_path = dex_candidates[0]

    def analyze(self) -> Dict:
        """Run full analysis"""
        report = {
            'jni_functions': {},
            'protocol_constants': [],
            'server_infrastructure': {},
            'credentials': {},
            'strings': {
                'ips': [],
                'urls': [],
                'domains': []
            }
        }

        if self.lib_path and self.lib_path.exists():
            report['jni_functions'] = self._analyze_jni()
            report['strings'] = self._extract_lib_strings()

        if self.dex_path and self.dex_path.exists():
            report['credentials'] = self._extract_credentials()
            dex_strings = self._extract_dex_strings()
            report['strings']['ips'].extend(dex_strings['ips'])
            report['strings']['urls'].extend(dex_strings['urls'])
            report['strings']['domains'].extend(dex_strings['domains'])

        # Dedupe strings
        for key in report['strings']:
            report['strings'][key] = sorted(set(report['strings'][key]))

        # Infer server infrastructure
        report['server_infrastructure'] = self._infer_infrastructure(report['strings'])

        return report

    def _analyze_jni(self) -> Dict[str, Dict]:
        """Extract JNI function symbols"""
        result = subprocess.run(
            ['objdump', '-T', str(self.lib_path)],
            capture_output=True, text=True
        )

        jni_funcs = {}
        for line in result.stdout.splitlines():
            for func_name in self.JNI_FUNCTIONS:
                if func_name in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        addr = parts[0]
                        size_match = re.search(r'([0-9a-f]+)\s+\w+', line)
                        size = size_match.group(1) if size_match else '0'
                        jni_funcs[func_name] = {
                            'address': f'0x{addr}',
                            'size': int(size, 16) if size != '0' else 0
                        }

        return jni_funcs

    def _extract_lib_strings(self) -> Dict[str, List[str]]:
        """Extract interesting strings from native lib"""
        result = subprocess.run(
            ['strings', str(self.lib_path)],
            capture_output=True, text=True
        )

        ips = []
        urls = []
        domains = []

        for line in result.stdout.splitlines():
            # IP addresses
            if re.match(r'(\d{1,3}\.){3}\d{1,3}', line):
                ips.append(line)

            # URLs
            if line.startswith('http://') or line.startswith('https://'):
                urls.append(line)

            # Domains
            if re.search(r'\.(cn|com|net|io)$', line) and not line.startswith('http'):
                domains.append(line)

        return {'ips': ips, 'urls': urls, 'domains': domains}

    def _extract_dex_strings(self) -> Dict[str, List[str]]:
        """Extract strings from DEX file"""
        result = subprocess.run(
            ['strings', str(self.dex_path)],
            capture_output=True, text=True
        )

        ips = []
        urls = []
        domains = []

        for line in result.stdout.splitlines():
            # IP addresses
            if re.match(r'(\d{1,3}\.){3}\d{1,3}', line):
                ips.append(line)

            # URLs (HiJoy/iWalkie specific)
            if ('iwalkie' in line.lower() or 'hijoy' in line.lower()) and \
               ('http://' in line or 'https://' in line):
                urls.append(line)

            # Agora/Baidu domains
            if re.search(r'(agora\.io|baidu\.com|iwalkie\.cn|hijoytech\.com)', line):
                domains.append(line)

        return {'ips': ips, 'urls': urls, 'domains': domains}

    def _extract_credentials(self) -> Dict[str, str]:
        """Extract Agora App ID and iWalkie appkey from DEX"""
        result = subprocess.run(
            ['strings', str(self.dex_path)],
            capture_output=True, text=True
        )

        creds = {}

        for line in result.stdout.splitlines():
            # Agora App ID (32-char hex)
            if re.match(r'^[a-f0-9]{32}$', line):
                # Verify context (should appear near Agora-related strings)
                creds['agora_app_id_candidate'] = line

            # iWalkie appkey (32-char hex, context check)
            if len(line) == 32 and re.match(r'^[a-f0-9]{32}$', line):
                creds['iwalkie_appkey_candidate'] = line

        return creds

    def _infer_infrastructure(self, strings: Dict) -> Dict:
        """Infer server infrastructure from extracted strings"""
        infra = {
            'ptt_servers': [],
            'update_endpoints': [],
            'known_ports': [],
        }

        # PTT servers (10.x.x.x IPs)
        for ip in strings['ips']:
            if ip.startswith('10.'):
                infra['ptt_servers'].append(ip)

        # Update endpoints
        for url in strings['urls']:
            if 'update' in url.lower() or 'aps' in url.lower():
                infra['update_endpoints'].append(url)

        # Port extraction from strings
        for s in strings.get('ports', []):
            try:
                port = int(s.lstrip(':'))
                if port in self.PROTOCOL_PORTS:
                    infra['known_ports'].append(port)
            except:
                pass

        return infra

    def generate_report(self, output_path: Optional[Path] = None):
        """Generate JSON report"""
        report = self.analyze()

        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {output_path}")
        else:
            print(json.dumps(report, indent=2))

        return report

    # ── live tracing (hijoy_trace native binary) ────────────────────────────

    TRACER_DIR    = Path(__file__).parent.parent.parent / "hijoy-trace"
    TRACER_BIN    = TRACER_DIR / "hijoy_trace"
    DEVICE_TRACER = "/data/local/tmp/hijoy_trace"
    PACKAGE       = "com.hijoytech.iwalkie30"

    def _tracer_ready(self) -> bool:
        return self.TRACER_BIN.exists()

    def tracer_build(self) -> bool:
        if not self.TRACER_BIN.parent.exists():
            return False
        r = subprocess.run(["bash", str(self.TRACER_DIR / "build.sh")],
                           capture_output=True, text=True)
        print(r.stdout + r.stderr)
        return r.returncode == 0

    def tracer_push(self) -> bool:
        if not self._tracer_ready():
            print("[!] tracer binary not built — run tracer_build() first")
            return False
        r = subprocess.run(
            ["adb", "push", str(self.TRACER_BIN), self.DEVICE_TRACER],
            capture_output=True, text=True)
        subprocess.run(
            ["adb", "shell", f"chmod 755 {self.DEVICE_TRACER}"],
            capture_output=True)
        return r.returncode == 0

    def _get_pid(self) -> int:
        r = subprocess.run(
            ["adb", "shell", f"pidof {self.PACKAGE}"],
            capture_output=True, text=True)
        try:
            return int(r.stdout.strip().split()[0])
        except (ValueError, IndexError):
            return 0

    def tracer_start(self, duration: int = 3600) -> list:
        """
        Attach hijoy_trace to the running iWalkie process.
        Returns a list of decoded JSON event dicts.
        Streams to stderr until timeout or process exit.
        """
        pid = self._get_pid()
        if not pid:
            raise RuntimeError(f"{self.PACKAGE} not running")

        out, err = [], []
        cmd = ["adb", "shell", f"su -c '{self.DEVICE_TRACER} {pid}'"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        import threading, time

        def drain_stderr():
            for line in proc.stderr:
                print(line, end="", flush=True)

        t = threading.Thread(target=drain_stderr, daemon=True)
        t.start()

        deadline = time.time() + duration
        events = []
        try:
            while time.time() < deadline:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"[raw] {line}")
        except KeyboardInterrupt:
            pass
        finally:
            proc.terminate()
            proc.wait()

        return events

def main():
    parser = argparse.ArgumentParser(
        description='HiJoy PTT Protocol Reverse Engineering Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze APK
  python3 hijoy_ptt_re.py --apk wecom.apk --output report.json

  # Analyze extracted lib + dex
  python3 hijoy_ptt_re.py --lib libhijoyptt.so --dex classes.dex
        """
    )

    parser.add_argument('--apk', type=Path, help='Path to APK file')
    parser.add_argument('--lib', type=Path, help='Path to libhijoyptt.so')
    parser.add_argument('--dex', type=Path, help='Path to classes.dex')
    parser.add_argument('--output', '-o', type=Path, help='Output JSON report path')

    args = parser.parse_args()

    if not (args.apk or (args.lib and args.dex)):
        parser.error('Must provide either --apk or both --lib and --dex')

    analyzer = HiJoyPTTRE(
        apk_path=args.apk,
        lib_path=args.lib,
        dex_path=args.dex
    )

    analyzer.generate_report(args.output)

if __name__ == '__main__':
    main()
