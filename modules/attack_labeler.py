"""
attack_labeler.py: ATT&CK technique ID auto-assignment for Ablation findings.

Maps confirmed finding types (by CWE class, sink type, or scanner name) to
MITRE ATT&CK technique IDs. Improves SKILLS report quality without requiring
manual T-ID tagging for every finding.

The mapping is based on the ATT&CK Enterprise and ICS matrices. Only technique
IDs with a clear mechanical mapping to a binary-level finding type are included;
ambiguous or context-dependent mappings are omitted.

Usage:
    from modules.attack_labeler import ATTACKLabeler
    tid, name = ATTACKLabeler.label(cwe_class='CWE-78')
    # Returns: ('T1059', 'Command and Scripting Interpreter')

    tids = ATTACKLabeler.label_finding(finding)
    # finding.severity, finding.sink, finding.cwe, etc.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# CWE → (T-ID, technique name) mapping
_CWE_TO_ATTCK: dict[str, tuple[str, str]] = {
    # Execution
    'CWE-78':  ('T1059.004', 'Unix Shell'),
    'CWE-88':  ('T1059.004', 'Unix Shell'),
    'CWE-77':  ('T1059',     'Command and Scripting Interpreter'),
    'CWE-94':  ('T1059.006', 'Python'),
    # Process injection
    'CWE-119': ('T1055',     'Process Injection'),
    'CWE-120': ('T1055',     'Process Injection'),
    'CWE-121': ('T1055',     'Process Injection'),
    'CWE-122': ('T1055.001', 'Dynamic-link Library Injection'),
    'CWE-416': ('T1055.012', 'Process Hollowing'),
    'CWE-415': ('T1055',     'Process Injection'),
    'CWE-787': ('T1055',     'Process Injection'),
    # Credential access
    'CWE-256': ('T1552.001', 'Credentials In Files'),
    'CWE-257': ('T1552.001', 'Credentials In Files'),
    'CWE-259': ('T1552.001', 'Credentials In Files'),
    'CWE-321': ('T1552.004', 'Private Keys'),
    'CWE-312': ('T1552',     'Unsecured Credentials'),
    'CWE-798': ('T1552.001', 'Credentials In Files'),
    # Defense evasion
    'CWE-116': ('T1027',     'Obfuscated Files or Information'),
    'CWE-327': ('T1027',     'Obfuscated Files or Information'),
    'CWE-326': ('T1027',     'Obfuscated Files or Information'),
    # Discovery
    'CWE-200': ('T1082',     'System Information Discovery'),
    'CWE-209': ('T1082',     'System Information Discovery'),
    # Privilege escalation
    'CWE-250': ('T1548',     'Abuse Elevation Control Mechanism'),
    'CWE-269': ('T1548',     'Abuse Elevation Control Mechanism'),
    'CWE-284': ('T1548',     'Abuse Elevation Control Mechanism'),
    # Exfiltration
    'CWE-319': ('T1048',     'Exfiltration Over Alternative Protocol'),
}

# Scanner module name → (T-ID, technique name)
_SCANNER_TO_ATTCK: dict[str, tuple[str, str]] = {
    'ProcessInjectionComboScanner':       ('T1055.003', 'Thread Execution Hijacking'),
    'AntiAnalysisStringDetector':         ('T1497',     'Virtualization/Sandbox Evasion'),
    'HardcodedCredentialScanner':         ('T1552.001', 'Credentials In Files'),
    'SignalHandlerRaceScanner':           ('T1499.004', 'Application or System Exploitation'),
    'DeadSecurityCheckScanner':           ('T1562.001', 'Disable or Modify Tools'),
    'NonConstantTimeComparatorScanner':   ('T1110',     'Brute Force'),
    'WeakPRNGAtSecuritySinkScanner':      ('T1110.001', 'Password Guessing'),
    'SizeofPtrDetector':                  ('T1499.004', 'Application or System Exploitation'),
    'TruncationAtSinkScanner':            ('T1499.004', 'Application or System Exploitation'),
    'SignedLengthArgScanner':             ('T1499.004', 'Application or System Exploitation'),
    'LethalTrifectaScanner':              ('T1048',     'Exfiltration Over Alternative Protocol'),
    'PromptInjectionSinkClassifier':      ('T1659',     'Content Injection'),
    'ELFAnomalyScanner':                  ('T1027.001', 'Binary Padding'),
    'FirmwarePKIChecker':                 ('T1542',     'Pre-OS Boot'),
    'MetacharFilterBypassScanner':        ('T1059',     'Command and Scripting Interpreter'),
    'DependencyConfusionScanner':         ('T1195.001', 'Compromise Software Dependencies and Development Tools'),
    'AgentAuthorityAudit':               ('T1548',     'Abuse Elevation Control Mechanism'),
}


@dataclass
class ATTACKLabel:
    technique_id: str
    technique_name: str
    source: str     # 'cwe' or 'scanner'

    def __str__(self) -> str:
        return f'{self.technique_id} — {self.technique_name}'


class ATTACKLabeler:
    """Auto-assign ATT&CK T-IDs from CWE class or scanner name."""

    @staticmethod
    def label_cwe(cwe_class: str) -> Optional[ATTACKLabel]:
        """Return ATT&CK label for a CWE class string, or None if not mapped."""
        entry = _CWE_TO_ATTCK.get(cwe_class.upper().strip())
        if entry:
            return ATTACKLabel(entry[0], entry[1], 'cwe')
        return None

    @staticmethod
    def label_scanner(scanner_name: str) -> Optional[ATTACKLabel]:
        """Return ATT&CK label for a scanner class name, or None if not mapped."""
        entry = _SCANNER_TO_ATTCK.get(scanner_name)
        if entry:
            return ATTACKLabel(entry[0], entry[1], 'scanner')
        return None

    @classmethod
    def label(cls, cwe_class: str = '', scanner_name: str = '') -> Optional[ATTACKLabel]:
        """Return the best ATT&CK label from CWE or scanner name.

        CWE takes precedence when both are provided.
        """
        if cwe_class:
            result = cls.label_cwe(cwe_class)
            if result:
                return result
        if scanner_name:
            return cls.label_scanner(scanner_name)
        return None

    @staticmethod
    def all_mappings() -> dict[str, list[dict]]:
        """Return all CWE and scanner mappings as a structured dict."""
        return {
            'cwe': [
                {'cwe': cwe, 'technique_id': tid, 'technique_name': name}
                for cwe, (tid, name) in _CWE_TO_ATTCK.items()
            ],
            'scanner': [
                {'scanner': scanner, 'technique_id': tid, 'technique_name': name}
                for scanner, (tid, name) in _SCANNER_TO_ATTCK.items()
            ],
        }
