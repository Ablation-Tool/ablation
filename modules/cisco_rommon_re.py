"""
cisco_rommon_re.py — ROMMON bypass analysis and Cisco boot chain reverse engineering.
Stdlib only. Analyzes config-register, boot integrity, TAm/Secure Boot, and platform bypass procedures.
"""

import re
import json
import sys
from typing import Optional


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------
_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


def _sev_sort_key(item: dict) -> int:
    return _SEV_ORDER.get(item.get('severity', 'INFO'), 99)


class ROMMONBypassRE:
    """
    Analyzes Cisco ROMMON configuration for password recovery / boot bypass vectors.

    ROMMON bypass chain:
    1. config-register 0x2142 => skip NVRAM on boot => no startup-config loaded => no passwords
    2. Reboot => ROMMON if confreg set, or directly to IOS with no config
    3. At IOS prompt (no config): copy startup-config running-config
    4. Change enable secret, set confreg back to 0x2102, reload
    """

    # Known config-register values and their meanings
    CONFIG_REGISTERS = {
        0x2102: ('NORMAL',       'Normal boot — loads startup-config from NVRAM'),
        0x2142: ('BYPASS',       'CRITICAL: Skip NVRAM — password recovery mode enabled'),
        0x2100: ('ROMMON',       'Boot directly to ROMMON (ROM Monitor) prompt'),
        0x2101: ('ROMMON_ALT',   'Boot to ROMMON with alternate boot system'),
        0x2104: ('NET_BOOT',     'Boot from network (TFTP) — no local config'),
        0x0000: ('ROMMON_HARD',  'Hard ROMMON — will not auto-boot IOS'),
    }

    # Bit definitions
    _BIT_IGNORE_NVRAM   = 0x40    # bit 6  — skip startup-config
    _BIT_BREAK_DISABLED = 0x100   # bit 8  — break key disabled
    _BIT_DIAG_BOOT      = 0x2000  # bit 13 — diagnostic boot

    # Boot field masks/values
    _BOOT_FIELD_MASK    = 0x000F

    def __init__(self):
        self.findings: list = []

    # ------------------------------------------------------------------
    # Config-register decoder
    # ------------------------------------------------------------------

    def analyze_confreg(self, value: int) -> dict:
        """
        Decode config-register bitmask.

        Bits [3:0] = boot field:
          0x0 = ROMMON
          0x1 = ROMMON alternate
          0x2-0xF = boot from flash/net (normal IOS boot sequence)
        Bit 6  (0x40)  = ignore NVRAM (password recovery when combined with boot != ROMMON)
        Bit 8  (0x100) = break disabled
        Bit 13 (0x2000) = diagnostic boot

        Returns dict with full decode + bypass_steps if dangerous.
        """
        boot_field = value & self._BOOT_FIELD_MASK
        ignore_nvram = bool(value & self._BIT_IGNORE_NVRAM)
        break_disabled = bool(value & self._BIT_BREAK_DISABLED)
        diag_boot = bool(value & self._BIT_DIAG_BOOT)

        # Look up known register
        known = self.CONFIG_REGISTERS.get(value)
        if known:
            state_label, description = known
        else:
            # Derive description from bits
            if boot_field == 0x0:
                state_label = 'ROMMON'
                description = 'Boot to ROMMON'
            elif boot_field == 0x1:
                state_label = 'ROMMON_ALT'
                description = 'Alternate ROMMON boot'
            elif ignore_nvram:
                state_label = 'BYPASS'
                description = 'Non-standard NVRAM-skip register'
            else:
                state_label = 'CUSTOM'
                description = f'Custom boot field 0x{boot_field:X}'

        # Severity
        if state_label == 'BYPASS' or ignore_nvram:
            severity = 'CRITICAL'
        elif state_label in ('ROMMON', 'ROMMON_ALT', 'ROMMON_HARD'):
            severity = 'HIGH'
        elif state_label == 'NET_BOOT':
            severity = 'HIGH'
        else:
            severity = 'INFO'

        # Build bypass steps when risk is present
        bypass_steps = []
        if ignore_nvram or state_label == 'BYPASS':
            bypass_steps = [
                'Device is already set to skip NVRAM on next boot.',
                'Power cycle or issue: reload',
                'IOS boots with empty running-config (no passwords).',
                'At privileged prompt: copy startup-config running-config',
                'conf t; enable secret <new_password>; config-register 0x2102; end',
                'copy running-config startup-config; reload',
            ]

        result = {
            'value_hex': f'0x{value:04X}',
            'value_int': value,
            'boot_field': f'0x{boot_field:X}',
            'ignore_nvram': ignore_nvram,
            'break_disabled': break_disabled,
            'diag_boot': diag_boot,
            'state_label': state_label,
            'severity': severity,
            'description': description,
            'bypass_steps': bypass_steps,
        }
        return result

    # ------------------------------------------------------------------
    # Boot integrity check (RESTCONF)
    # ------------------------------------------------------------------

    def check_boot_integrity(self, restconf_data: dict) -> list:
        """
        From RESTCONF boot config data, check:
        - Secure Boot status
        - IOS image verification disabled
        - Boot variable points to expected image
        - Trust anchor (TAm) present
        Returns [{severity, title, detail}]
        """
        findings = []

        if not restconf_data:
            return findings

        def _search(d, key):
            """Recursive key search in nested dict/list."""
            if isinstance(d, dict):
                for k, v in d.items():
                    if k.lower() == key.lower():
                        return v
                    found = _search(v, key)
                    if found is not None:
                        return found
            elif isinstance(d, list):
                for item in d:
                    found = _search(item, key)
                    if found is not None:
                        return found
            return None

        # Secure Boot enabled?
        secure_boot = _search(restconf_data, 'secure-boot')
        if secure_boot is None:
            findings.append({
                'severity': 'HIGH',
                'title': 'Secure Boot Status Unknown',
                'detail': 'secure-boot key not found in RESTCONF data; cannot confirm boot integrity enforcement.',
            })
        elif str(secure_boot).lower() in ('false', '0', 'disabled'):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'Secure Boot Disabled',
                'detail': f'RESTCONF reports secure-boot={secure_boot}; unsigned images can be loaded.',
            })
        else:
            findings.append({
                'severity': 'INFO',
                'title': 'Secure Boot Enabled',
                'detail': f'secure-boot={secure_boot}',
            })

        # IOS image verification
        img_verify = _search(restconf_data, 'image-verification') or _search(restconf_data, 'ios-image-verification')
        if img_verify is not None and str(img_verify).lower() in ('false', '0', 'disabled'):
            findings.append({
                'severity': 'HIGH',
                'title': 'IOS Image Verification Disabled',
                'detail': 'image-verification disabled; no cryptographic check on IOS binary at boot.',
            })

        # Boot variable check
        boot_var = _search(restconf_data, 'boot-variable') or _search(restconf_data, 'boot-system')
        if boot_var:
            if 'tftp' in str(boot_var).lower() or 'ftp' in str(boot_var).lower():
                findings.append({
                    'severity': 'HIGH',
                    'title': 'Network Boot Variable Configured',
                    'detail': f'Boot variable points to network location: {boot_var}. Image integrity depends on network path security.',
                })
            else:
                findings.append({
                    'severity': 'INFO',
                    'title': 'Boot Variable',
                    'detail': f'boot-variable={boot_var}',
                })

        # Trust anchor (TAm)
        tam = _search(restconf_data, 'trust-anchor') or _search(restconf_data, 'tam') or _search(restconf_data, 'platform-hardware-tam')
        if tam is None:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'TAm (Trust Anchor) Not Found in RESTCONF Data',
                'detail': 'Trust Anchor Module data absent; cannot verify hardware root-of-trust.',
            })

        # Confreg from RESTCONF
        confreg = _search(restconf_data, 'config-register') or _search(restconf_data, 'confreg')
        if confreg is not None:
            try:
                val = int(str(confreg), 16) if str(confreg).startswith('0x') else int(str(confreg), 0)
                decoded = self.analyze_confreg(val)
                if decoded['severity'] in ('CRITICAL', 'HIGH'):
                    findings.append({
                        'severity': decoded['severity'],
                        'title': f"Dangerous config-register in RESTCONF: {decoded['value_hex']}",
                        'detail': decoded['description'],
                    })
            except (ValueError, TypeError):
                pass

        return sorted(findings, key=_sev_sort_key)

    # ------------------------------------------------------------------
    # ROMMON variable parser
    # ------------------------------------------------------------------

    def analyze_rommon_vars(self, vars_text: str) -> dict:
        """
        Parse 'show romvar' / 'show boot' output text:
        - CONFREG= value
        - BOOT= image path
        - BST= (boot status)
        - ROMmon version
        Returns {confreg, boot_image, rommon_version, bypass_risk, raw_vars}
        """
        result = {
            'confreg': None,
            'confreg_decoded': None,
            'boot_image': None,
            'rommon_version': None,
            'bst': None,
            'bypass_risk': False,
            'raw_vars': {},
        }

        for line in vars_text.splitlines():
            line = line.strip()

            # CONFREG
            m = re.search(r'CONFREG\s*[=:]\s*(0x[0-9A-Fa-f]+|\d+)', line, re.IGNORECASE)
            if m:
                raw = m.group(1)
                try:
                    val = int(raw, 16) if raw.startswith('0x') else int(raw)
                    result['confreg'] = f'0x{val:04X}'
                    decoded = self.analyze_confreg(val)
                    result['confreg_decoded'] = decoded
                    result['bypass_risk'] = decoded['severity'] in ('CRITICAL', 'HIGH')
                except ValueError:
                    result['confreg'] = raw
                result['raw_vars']['CONFREG'] = raw

            # BOOT image
            m = re.search(r'(?:BOOT|boot system)\s*[=:]\s*(\S+)', line, re.IGNORECASE)
            if m:
                result['boot_image'] = m.group(1)
                result['raw_vars']['BOOT'] = m.group(1)

            # BST (boot status)
            m = re.search(r'BST\s*[=:]\s*(\S+)', line, re.IGNORECASE)
            if m:
                result['bst'] = m.group(1)
                result['raw_vars']['BST'] = m.group(1)

            # ROMmon version
            m = re.search(
                r'(?:ROMmon|ROM Monitor|ROMMON)\s+[Vv]ersion\s+[=:]?\s*(\S+)',
                line, re.IGNORECASE
            )
            if m:
                result['rommon_version'] = m.group(1)

            # Generic KEY=VALUE pairs
            m = re.match(r'^([A-Z_]+)\s*=\s*(.+)$', line)
            if m:
                result['raw_vars'][m.group(1)] = m.group(2).strip()

        return result

    # ------------------------------------------------------------------
    # Bypass procedure generator
    # ------------------------------------------------------------------

    def generate_bypass_steps(self, platform: str = 'ios') -> list:
        """
        Return ordered list of ROMMON bypass steps for the given platform.
        platform: 'ios', 'ios-xe', 'ios-xr', 'asa', 'nxos'
        """
        platform = platform.lower()

        if platform in ('ios', 'ios-xe'):
            return [
                '[Physical/Console] Connect to console port (9600-8-N-1).',
                '[Power] Power cycle the device (pull power or: reload).',
                '[Timing] Send BREAK within 60 seconds of power-up to interrupt boot.',
                '         On Linux: Ctrl+A then send break in minicom; or use: send-break in screen.',
                '[ROMMON] At rommon> prompt: confreg 0x2142',
                '[ROMMON] rommon> reset  (device reboots)',
                '[IOS] Device boots with no startup-config; no enable password.',
                '[IOS] Router> enable  (no password required)',
                '[IOS] Router# copy startup-config running-config',
                '[IOS] Router# configure terminal',
                '[IOS]   enable secret <new_secure_password>',
                '[IOS]   config-register 0x2102',
                '[IOS] Router(config)# end',
                '[IOS] Router# copy running-config startup-config',
                '[IOS] Router# reload',
                '[Verify] After reload: confirm confreg is 0x2102 with: show version | include register',
            ]

        if platform == 'ios-xr':
            return [
                '[Physical/Console] Console access required (115200-8-N-1 on XR).',
                '[Power] Power cycle or: admin reload location all.',
                '[ROMMON] Press any key / BREAK within 5s to enter ROMMON on XR.',
                '[ROMMON] At rommon> prompt: set ConfrugRegister 0x0  (forces ROMMON on next boot)',
                '         Note: IOS-XR password recovery uses a different procedure — XML agent or disk boot.',
                '[XR Recovery] Boot from USB/disk with IOS-XR rescue image.',
                '[XR Recovery] Mount disk; edit /misc/config/users (remove password entry).',
                '[XR Recovery] Or: admin> username <name> secret <new>; commit',
                '[Verify] Confirm system integrity: show platform integrity',
            ]

        if platform == 'asa':
            return [
                '[Physical/Console] Console connection required (9600-8-N-1).',
                '[Power] Power cycle the ASA.',
                '[Timing] Send BREAK/ESC within 10 seconds to enter ROMMON.',
                '[ROMMON] rommon> confreg  (displays current config-register)',
                '[ROMMON] rommon> confreg 0x41  (bit 6 set = ignore startup config)',
                '[ROMMON] rommon> boot  (or let it auto-boot)',
                '[ASA] ASA boots with factory-default config; no enable password.',
                '[ASA] ciscoasa# copy startup-config running-config',
                '[ASA] ciscoasa# configure terminal',
                '[ASA]   enable password <new_password>',
                '[ASA]   no config-register  (or: config-register 0x1)',
                '[ASA] ciscoasa(config)# end',
                '[ASA] ciscoasa# write memory',
                '[ASA] ciscoasa# reload',
                '[Note] ASA confreg bit 6 (0x40) = ignore config, not 0x2142 like IOS.',
            ]

        if platform == 'nxos':
            return [
                '[Physical/Console] Console connection required.',
                '[Power] Power cycle or: reload.',
                '[Boot] NX-OS does not use config-register; password recovery via loader> prompt.',
                '[Loader] At loader> prompt (interrupt boot with Ctrl+]):',
                '         loader> cmdline recoverymode=1',
                '         loader> boot nxos.bin',
                '[NX-OS] System boots in password-recovery mode (limited shell).',
                '[NX-OS] switch(boot)# configure terminal',
                '[NX-OS] switch(boot-config)# admin-password <new_password>',
                '[NX-OS] switch(boot)# load-nxos',
                '[NX-OS] After full boot: configure terminal; username admin password <new>',
                '[Note] Some NX-OS platforms require secure-boot-grub and loader interaction differs.',
            ]

        # Default fallback
        return [
            f'[Unknown platform: {platform}] Consult platform-specific ROMMON documentation.',
            'General: console access + power cycle + BREAK timing to enter ROMMON.',
            'Modify confreg to ignore NVRAM, reboot, reconfigure credentials.',
        ]

    # ------------------------------------------------------------------
    # Combined analyze
    # ------------------------------------------------------------------

    def analyze(self, config_text: str = None, confreg_value: int = None) -> dict:
        """Run all checks, return unified findings dict."""
        result = {
            'findings': [],
            'confreg': None,
            'bypass_steps': [],
            'rommon_vars': None,
            'platform': None,
        }

        # If direct confreg value provided
        if confreg_value is not None:
            decoded = self.analyze_confreg(confreg_value)
            result['confreg'] = decoded

            if decoded['severity'] in ('CRITICAL', 'HIGH'):
                result['findings'].append({
                    'severity': decoded['severity'],
                    'title': f"Dangerous config-register: {decoded['value_hex']}",
                    'detail': decoded['description'],
                    'remediation': 'Set config-register 0x2102 after securing enable credentials.',
                })
                result['bypass_steps'] = decoded.get('bypass_steps', [])

        # Parse config text if provided
        if config_text:
            platform = self._detect_platform(config_text)
            result['platform'] = platform

            # Look for confreg in config
            m = re.search(r'config-register\s+(0x[0-9A-Fa-f]+)', config_text, re.IGNORECASE)
            if m:
                raw = m.group(1)
                try:
                    val = int(raw, 16)
                    decoded = self.analyze_confreg(val)
                    result['confreg'] = decoded

                    if decoded['severity'] in ('CRITICAL', 'HIGH'):
                        result['findings'].append({
                            'severity': decoded['severity'],
                            'title': f"Dangerous config-register: {decoded['value_hex']}",
                            'detail': decoded['description'],
                            'remediation': 'Set: config-register 0x2102',
                        })
                        result['bypass_steps'] = self.generate_bypass_steps(platform)
                    else:
                        result['findings'].append({
                            'severity': 'INFO',
                            'title': f"config-register: {decoded['value_hex']}",
                            'detail': decoded['description'],
                            'remediation': None,
                        })
                except ValueError:
                    pass
            else:
                # No confreg in config — default 0x2102 assumed but check if 0x2142 mentioned
                if '2142' in config_text:
                    result['findings'].append({
                        'severity': 'HIGH',
                        'title': 'Possible ROMMON Bypass Reference (2142)',
                        'detail': 'String "2142" found in config without explicit config-register directive; review manually.',
                        'remediation': 'Audit config-register; set explicitly to 0x2102.',
                    })

            # Try to parse as romvar output too (if it looks like show romvar)
            if 'CONFREG=' in config_text.upper() or 'rommon' in config_text.lower():
                rommon_vars = self.analyze_rommon_vars(config_text)
                result['rommon_vars'] = rommon_vars
                if rommon_vars.get('bypass_risk') and not result['bypass_steps']:
                    result['bypass_steps'] = self.generate_bypass_steps(platform)

            # Check no-service password-encryption cross-ref
            if re.search(r'no\s+service\s+password-encryption', config_text, re.IGNORECASE):
                result['findings'].append({
                    'severity': 'HIGH',
                    'title': 'No Password Encryption (ROMMON context)',
                    'detail': 'With ROMMON bypass, cleartext passwords in config are directly recoverable.',
                    'remediation': 'Enable service password-encryption; use type-9 secrets.',
                })

        result['findings'] = sorted(result['findings'], key=_sev_sort_key)
        return result

    # ------------------------------------------------------------------
    # Platform detection helper
    # ------------------------------------------------------------------

    def _detect_platform(self, text: str) -> str:
        head = '\n'.join(text.splitlines()[:15]).lower()
        if any(t in head for t in ('asa version', 'pixos', 'adaptive security appliance')):
            return 'asa'
        if any(t in head for t in ('nx-os', 'nexus', 'nxos')):
            return 'nxos'
        if 'ios xr' in head or 'iosxr' in head:
            return 'ios-xr'
        if 'ios-xe' in head:
            return 'ios-xe'
        return 'ios'

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def report(self) -> str:
        # This is called after analyze() sets self.findings
        lines = ['=== ROMMON Bypass RE ===']
        for f in self.findings:
            lines.append(f"[{f.get('severity')}] {f.get('title')} — {f.get('detail','')}")
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Secure Boot analysis
# ---------------------------------------------------------------------------

class SecureBootRE:
    """
    Analyzes Cisco IOS-XE Secure Boot and Trust Anchor (TAm) configuration.

    Cisco Secure Boot chain:
    ROMMON (ROM, immutable) -> Boot Loader (signed) -> IOS-XE (signed) -> TAm (TPM-like)

    Verification commands (from RESTCONF or config):
    - show platform integrity
    - show boot integrity oper-data
    - show platform hardware tam
    """

    SECURE_BOOT_PATHS = [
        '/restconf/data/Cisco-IOS-XE-boot-integrity-events:boot-integrity-oper-data',
        '/restconf/data/Cisco-IOS-XE-platform-integrity-oper:platform-integrity',
    ]

    def __init__(self):
        self.pcr_digests: dict = {}     # TPM PCR register values
        self.image_hash: Optional[str] = None   # Expected IOS image hash
        self.boot_log: list = []         # Boot integrity events

    # ------------------------------------------------------------------
    # Parse 'show platform integrity' output
    # ------------------------------------------------------------------

    def parse_integrity_output(self, text: str) -> dict:
        """
        Parse 'show platform integrity' text output.
        Extracts:
        - PCR0-9 register values (SHA256 hex)
        - Boot loader hash
        - OS image hash
        - Signature verification status
        Returns {pcr_registers, image_hash, boot_hash, verified, findings}
        """
        result = {
            'pcr_registers': {},
            'image_hash': None,
            'boot_hash': None,
            'boot_loader_version': None,
            'ios_version': None,
            'verified': None,
            'signature_valid': None,
            'findings': [],
        }

        for line in text.splitlines():
            stripped = line.strip()

            # PCR registers: "PCR0: <hex>" or "Platform PCR[0]: <hex>"
            m = re.search(r'PCR\s*\[?\s*(\d+)\s*\]?\s*[=:]\s*([0-9A-Fa-f]{32,})', stripped)
            if m:
                pcr_num = int(m.group(1))
                pcr_val = m.group(2).upper()
                result['pcr_registers'][pcr_num] = pcr_val
                self.pcr_digests[pcr_num] = pcr_val

            # Image hash / OS hash
            m = re.search(r'(?:IOS|OS)\s+(?:Image\s+)?[Hh]ash\s*[=:]\s*([0-9A-Fa-f]{32,})', stripped)
            if m:
                result['image_hash'] = m.group(1).upper()
                self.image_hash = result['image_hash']

            # Boot loader hash
            m = re.search(r'[Bb]oot\s+[Ll]oader\s+[Hh]ash\s*[=:]\s*([0-9A-Fa-f]{32,})', stripped)
            if m:
                result['boot_hash'] = m.group(1).upper()

            # Boot loader version
            m = re.search(r'[Bb]oot\s+[Ll]oader\s+[Vv]ersion\s*[=:]\s*(\S+)', stripped)
            if m:
                result['boot_loader_version'] = m.group(1)

            # IOS version from integrity output
            m = re.search(r'(?:IOS|Software)\s+[Vv]ersion\s*[=:]\s*(\S+)', stripped)
            if m:
                result['ios_version'] = m.group(1)

            # Signature verification
            m = re.search(r'[Ss]ignature\s+[Vv]erif(?:ication|ied)\s*[=:]\s*(\S+)', stripped)
            if m:
                val = m.group(1).lower()
                result['signature_valid'] = val in ('pass', 'ok', 'valid', 'true', 'verified')

            # Verified status
            m = re.search(r'[Vv]erif(?:ied|ication)\s+[Ss]tatus\s*[=:]\s*(\S+)', stripped)
            if m:
                val = m.group(1).lower()
                result['verified'] = val in ('pass', 'ok', 'valid', 'true', 'verified')

        # Build findings from parsed data
        findings = []

        if result['signature_valid'] is False:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'Boot Signature Verification Failed',
                'detail': 'IOS image signature verification reports FAIL — possible tampered image.',
            })
        elif result['signature_valid'] is None and result['image_hash'] is None:
            findings.append({
                'severity': 'HIGH',
                'title': 'Boot Integrity Data Incomplete',
                'detail': 'Could not parse signature status or image hash from platform integrity output.',
            })
        else:
            findings.append({
                'severity': 'INFO',
                'title': 'Boot Signature Verified',
                'detail': f"image_hash={result['image_hash'] or 'N/A'} signature_valid={result['signature_valid']}",
            })

        if not result['pcr_registers']:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'No PCR Values Found',
                'detail': 'TPM PCR registers not found in integrity output; TAm attestation cannot be confirmed.',
            })
        else:
            # PCR0 all-zeros is suspicious (uninitialized or zeroed)
            pcr0 = result['pcr_registers'].get(0, '')
            if pcr0 and all(c == '0' for c in pcr0):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'PCR0 is All-Zeros',
                    'detail': 'PCR0 = 0x000...000 — may indicate uninitialized TAm or measurement failure.',
                })

        result['findings'] = sorted(findings, key=lambda x: _SEV_ORDER.get(x['severity'], 99))
        self.boot_log.extend(result['findings'])
        return result

    # ------------------------------------------------------------------
    # TAm GUID extraction
    # ------------------------------------------------------------------

    def detect_tam_guid(self, text: str) -> str:
        """Extract TAm device GUID from 'show platform hardware tam' output."""
        for line in text.splitlines():
            # UUID/GUID pattern: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            m = re.search(
                r'\b([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\b',
                line
            )
            if m:
                return m.group(1).upper()
            # Some TAm outputs show GUID without dashes: 32 hex chars
            m = re.search(
                r'(?:GUID|TAm\s+ID|Device\s+ID|Unique\s+ID)\s*[=:]\s*([0-9A-Fa-f]{32})\b',
                line, re.IGNORECASE
            )
            if m:
                raw = m.group(1).upper()
                # Format as UUID
                return f'{raw[0:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:32]}'
        return ''

    # ------------------------------------------------------------------
    # Top-level analyze
    # ------------------------------------------------------------------

    def analyze(self, integrity_text: str = None, restconf_data: dict = None) -> dict:
        """Run all SecureBoot checks from available inputs."""
        result = {
            'integrity': None,
            'tam_guid': None,
            'restconf_findings': [],
            'all_findings': [],
        }

        if integrity_text:
            result['integrity'] = self.parse_integrity_output(integrity_text)
            result['all_findings'].extend(result['integrity'].get('findings', []))
            # Try TAm GUID extraction from same text
            guid = self.detect_tam_guid(integrity_text)
            if guid:
                result['tam_guid'] = guid

        if restconf_data:
            rommon_re = ROMMONBypassRE()
            restconf_findings = rommon_re.check_boot_integrity(restconf_data)
            result['restconf_findings'] = restconf_findings
            result['all_findings'].extend(restconf_findings)

        result['all_findings'] = sorted(result['all_findings'], key=_sev_sort_key)
        return result


# ---------------------------------------------------------------------------
# Top-level entry function
# ---------------------------------------------------------------------------

def analyze_rommon(config_text_or_confreg: str, platform: str = 'ios') -> dict:
    """
    Top-level entry. Accepts config text or hex confreg value string like '0x2142'.
    Returns unified findings dict.
    """
    engine = ROMMONBypassRE()

    # Detect if it's a raw confreg hex value
    stripped = config_text_or_confreg.strip()
    if re.match(r'^0x[0-9A-Fa-f]+$', stripped, re.IGNORECASE):
        try:
            val = int(stripped, 16)
            result = engine.analyze(confreg_value=val)
            result['platform'] = platform
            result['bypass_steps'] = engine.generate_bypass_steps(platform)
            return result
        except ValueError:
            pass

    # Treat as config/romvar text
    result = engine.analyze(config_text=stripped)
    if not result.get('platform'):
        result['platform'] = platform
    if not result.get('bypass_steps') and result.get('confreg', {}) and \
            result['confreg'].get('severity') in ('CRITICAL', 'HIGH'):
        result['bypass_steps'] = engine.generate_bypass_steps(result['platform'])
    return result


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else None
    if not src:
        print("Usage: cisco_rommon_re.py <config_file|0xCONFREG>")
        sys.exit(1)

    if src.strip().startswith('0x') or src.strip().startswith('0X'):
        val = int(src.strip(), 16)
        engine = ROMMONBypassRE()
        result = engine.analyze(confreg_value=val)
    elif src == '-':
        text = sys.stdin.read()
        result = analyze_rommon(text)
    else:
        text = open(src, errors='replace').read()
        result = analyze_rommon(text)

    print(json.dumps(result, indent=2, default=str))
    for f in result.get('findings', []):
        print(f"[{f.get('severity', 'INFO')}] {f.get('title', '')} — {f.get('detail', '')[:120]}")
