#!/usr/bin/env python3
"""
MITRE ATT&CK technique tagging for findings enrichment.
Maps finding type keywords to ATT&CK technique IDs.
"""

# Tactic order mirrors the ATT&CK kill chain
TACTIC_ORDER = [
    'Reconnaissance',
    'Resource Development',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
]

# Maps (keyword, ...) -> {id, name, tactic}
# Keywords are lowercased fragments matched against finding type + description.
# Ordered from most specific to least specific; all matches are returned.
ATTCK_MAP = {
    # --- Initial Access ---
    'valid account': {
        'id': 'T1078',
        'name': 'Valid Accounts',
        'tactic': 'Initial Access',
    },
    'default cred': {
        'id': 'T1078',
        'name': 'Valid Accounts',
        'tactic': 'Initial Access',
    },
    'default_cred': {
        'id': 'T1078',
        'name': 'Valid Accounts',
        'tactic': 'Initial Access',
    },
    'exploit public': {
        'id': 'T1190',
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
    },
    'public-facing': {
        'id': 'T1190',
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
    },
    'unauth access': {
        'id': 'T1190',
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
    },
    'unauthenticated': {
        'id': 'T1190',
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
    },
    'external remote': {
        'id': 'T1133',
        'name': 'External Remote Services',
        'tactic': 'Initial Access',
    },
    'vpn': {
        'id': 'T1133',
        'name': 'External Remote Services',
        'tactic': 'Initial Access',
    },
    'webvpn': {
        'id': 'T1133',
        'name': 'External Remote Services',
        'tactic': 'Initial Access',
    },
    'phishing': {
        'id': 'T1566',
        'name': 'Phishing',
        'tactic': 'Initial Access',
    },
    'supply chain': {
        'id': 'T1195',
        'name': 'Supply Chain Compromise',
        'tactic': 'Initial Access',
    },

    # --- Execution ---
    'command and scripting': {
        'id': 'T1059',
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
    },
    'powershell': {
        'id': 'T1059.001',
        'name': 'PowerShell',
        'tactic': 'Execution',
    },
    'script interpreter': {
        'id': 'T1059',
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
    },
    'native api': {
        'id': 'T1106',
        'name': 'Native API',
        'tactic': 'Execution',
    },
    'scheduled task': {
        'id': 'T1053',
        'name': 'Scheduled Task/Job',
        'tactic': 'Execution',
    },
    'cron job': {
        'id': 'T1053.003',
        'name': 'Cron',
        'tactic': 'Execution',
    },
    'jar upload': {
        'id': 'T1059',
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
    },
    'rce': {
        'id': 'T1059',
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
    },
    'jdwp': {
        'id': 'T1059',
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
    },
    'code eval': {
        'id': 'T1059',
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
    },

    # --- Persistence ---
    'boot autostart': {
        'id': 'T1547',
        'name': 'Boot/Logon Autostart Execution',
        'tactic': 'Persistence',
    },
    'launchagent': {
        'id': 'T1543.001',
        'name': 'Launch Agent',
        'tactic': 'Persistence',
    },
    'launchdaemon': {
        'id': 'T1543.004',
        'name': 'Launch Daemon',
        'tactic': 'Persistence',
    },
    'run key': {
        'id': 'T1547.001',
        'name': 'Registry Run Keys / Startup Folder',
        'tactic': 'Persistence',
    },
    'service create': {
        'id': 'T1543',
        'name': 'Create or Modify System Process',
        'tactic': 'Persistence',
    },
    'windows service': {
        'id': 'T1543.003',
        'name': 'Windows Service',
        'tactic': 'Persistence',
    },
    'dll hijack': {
        'id': 'T1574',
        'name': 'Hijack Execution Flow',
        'tactic': 'Persistence',
    },
    'dll sideload': {
        'id': 'T1574.002',
        'name': 'DLL Side-Loading',
        'tactic': 'Persistence',
    },
    'dyld': {
        'id': 'T1574',
        'name': 'Hijack Execution Flow',
        'tactic': 'Persistence',
    },
    'oauth token': {
        'id': 'T1550.001',
        'name': 'Application Access Token',
        'tactic': 'Persistence',
    },
    'refresh token': {
        'id': 'T1550.001',
        'name': 'Application Access Token',
        'tactic': 'Persistence',
    },

    # --- Privilege Escalation ---
    'privilege escalat': {
        'id': 'T1068',
        'name': 'Exploitation for Privilege Escalation',
        'tactic': 'Privilege Escalation',
    },
    'privesc': {
        'id': 'T1068',
        'name': 'Exploitation for Privilege Escalation',
        'tactic': 'Privilege Escalation',
    },
    'suid': {
        'id': 'T1548.001',
        'name': 'Setuid and Setgid',
        'tactic': 'Privilege Escalation',
    },
    'setuid': {
        'id': 'T1548.001',
        'name': 'Setuid and Setgid',
        'tactic': 'Privilege Escalation',
    },
    'sudo': {
        'id': 'T1548.003',
        'name': 'Sudo and Sudo Caching',
        'tactic': 'Privilege Escalation',
    },
    'nopasswd': {
        'id': 'T1548.003',
        'name': 'Sudo and Sudo Caching',
        'tactic': 'Privilege Escalation',
    },
    'uac bypass': {
        'id': 'T1548.002',
        'name': 'Bypass User Account Control',
        'tactic': 'Privilege Escalation',
    },
    'process inject': {
        'id': 'T1055',
        'name': 'Process Injection',
        'tactic': 'Privilege Escalation',
    },
    'token impersonat': {
        'id': 'T1134',
        'name': 'Access Token Manipulation',
        'tactic': 'Privilege Escalation',
    },
    'access token manipulat': {
        'id': 'T1134',
        'name': 'Access Token Manipulation',
        'tactic': 'Privilege Escalation',
    },
    'weak service': {
        'id': 'T1574.010',
        'name': 'Services File Permissions Weakness',
        'tactic': 'Privilege Escalation',
    },

    # --- Defense Evasion ---
    'obfuscat': {
        'id': 'T1027',
        'name': 'Obfuscated Files or Information',
        'tactic': 'Defense Evasion',
    },
    'encoded payload': {
        'id': 'T1027',
        'name': 'Obfuscated Files or Information',
        'tactic': 'Defense Evasion',
    },
    'base64': {
        'id': 'T1027',
        'name': 'Obfuscated Files or Information',
        'tactic': 'Defense Evasion',
    },
    'deobfuscat': {
        'id': 'T1140',
        'name': 'Deobfuscate/Decode Files or Information',
        'tactic': 'Defense Evasion',
    },
    'no pie': {
        'id': 'T1027',
        'name': 'Obfuscated Files or Information',
        'tactic': 'Defense Evasion',
    },
    'no nx': {
        'id': 'T1055',
        'name': 'Process Injection',
        'tactic': 'Defense Evasion',
    },
    'no relro': {
        'id': 'T1027',
        'name': 'Obfuscated Files or Information',
        'tactic': 'Defense Evasion',
    },
    'aslr disabled': {
        'id': 'T1562',
        'name': 'Impair Defenses',
        'tactic': 'Defense Evasion',
    },
    'masquerad': {
        'id': 'T1036',
        'name': 'Masquerading',
        'tactic': 'Defense Evasion',
    },
    'signed binary': {
        'id': 'T1218',
        'name': 'System Binary Proxy Execution',
        'tactic': 'Defense Evasion',
    },
    'living off the land': {
        'id': 'T1218',
        'name': 'System Binary Proxy Execution',
        'tactic': 'Defense Evasion',
    },
    'lotl': {
        'id': 'T1218',
        'name': 'System Binary Proxy Execution',
        'tactic': 'Defense Evasion',
    },

    # --- Credential Access ---
    'credential dump': {
        'id': 'T1003',
        'name': 'OS Credential Dumping',
        'tactic': 'Credential Access',
    },
    'lsass': {
        'id': 'T1003.001',
        'name': 'LSASS Memory',
        'tactic': 'Credential Access',
    },
    'shadow file': {
        'id': 'T1003.008',
        'name': '/etc/passwd and /etc/shadow',
        'tactic': 'Credential Access',
    },
    'htpasswd': {
        'id': 'T1003',
        'name': 'OS Credential Dumping',
        'tactic': 'Credential Access',
    },
    'brute force': {
        'id': 'T1110',
        'name': 'Brute Force',
        'tactic': 'Credential Access',
    },
    'password spray': {
        'id': 'T1110.003',
        'name': 'Password Spraying',
        'tactic': 'Credential Access',
    },
    'unsecured credential': {
        'id': 'T1552',
        'name': 'Unsecured Credentials',
        'tactic': 'Credential Access',
    },
    'aws_credential': {
        'id': 'T1552.001',
        'name': 'Credentials In Files',
        'tactic': 'Credential Access',
    },
    'docker_config': {
        'id': 'T1552.001',
        'name': 'Credentials In Files',
        'tactic': 'Credential Access',
    },
    'api token': {
        'id': 'T1552.001',
        'name': 'Credentials In Files',
        'tactic': 'Credential Access',
    },
    'api key': {
        'id': 'T1552.001',
        'name': 'Credentials In Files',
        'tactic': 'Credential Access',
    },
    'ssh private key': {
        'id': 'T1552.004',
        'name': 'Private Keys',
        'tactic': 'Credential Access',
    },
    'private key': {
        'id': 'T1552.004',
        'name': 'Private Keys',
        'tactic': 'Credential Access',
    },
    'kerberoast': {
        'id': 'T1558.003',
        'name': 'Kerberoasting',
        'tactic': 'Credential Access',
    },
    'jwt': {
        'id': 'T1552.001',
        'name': 'Credentials In Files',
        'tactic': 'Credential Access',
    },
    'forged_jwt': {
        'id': 'T1134.001',
        'name': 'Token Impersonation/Theft',
        'tactic': 'Credential Access',
    },
    'jwt forge': {
        'id': 'T1134.001',
        'name': 'Token Impersonation/Theft',
        'tactic': 'Credential Access',
    },
    'token forge': {
        'id': 'T1134.001',
        'name': 'Token Impersonation/Theft',
        'tactic': 'Credential Access',
    },
    'keychain': {
        'id': 'T1555.001',
        'name': 'Keychain',
        'tactic': 'Credential Access',
    },
    'ntlm hash': {
        'id': 'T1003.001',
        'name': 'LSASS Memory',
        'tactic': 'Credential Access',
    },

    # --- Discovery ---
    'network service': {
        'id': 'T1046',
        'name': 'Network Service Discovery',
        'tactic': 'Discovery',
    },
    'port scan': {
        'id': 'T1046',
        'name': 'Network Service Discovery',
        'tactic': 'Discovery',
    },
    'subnet scan': {
        'id': 'T1046',
        'name': 'Network Service Discovery',
        'tactic': 'Discovery',
    },
    'system information': {
        'id': 'T1082',
        'name': 'System Information Discovery',
        'tactic': 'Discovery',
    },
    'platform detect': {
        'id': 'T1082',
        'name': 'System Information Discovery',
        'tactic': 'Discovery',
    },
    'os detect': {
        'id': 'T1082',
        'name': 'System Information Discovery',
        'tactic': 'Discovery',
    },
    'file and directory': {
        'id': 'T1083',
        'name': 'File and Directory Discovery',
        'tactic': 'Discovery',
    },
    'directory traversal': {
        'id': 'T1083',
        'name': 'File and Directory Discovery',
        'tactic': 'Discovery',
    },
    'account discovery': {
        'id': 'T1087',
        'name': 'Account Discovery',
        'tactic': 'Discovery',
    },
    'user enumerat': {
        'id': 'T1087',
        'name': 'Account Discovery',
        'tactic': 'Discovery',
    },
    'remote system discovery': {
        'id': 'T1018',
        'name': 'Remote System Discovery',
        'tactic': 'Discovery',
    },
    'network scan': {
        'id': 'T1018',
        'name': 'Remote System Discovery',
        'tactic': 'Discovery',
    },
    'process enumerat': {
        'id': 'T1057',
        'name': 'Process Discovery',
        'tactic': 'Discovery',
    },
    'snmp': {
        'id': 'T1082',
        'name': 'System Information Discovery',
        'tactic': 'Discovery',
    },
    'fabric inventor': {
        'id': 'T1018',
        'name': 'Remote System Discovery',
        'tactic': 'Discovery',
    },

    # --- Lateral Movement ---
    'remote service': {
        'id': 'T1021',
        'name': 'Remote Services',
        'tactic': 'Lateral Movement',
    },
    'smb': {
        'id': 'T1021.002',
        'name': 'SMB/Windows Admin Shares',
        'tactic': 'Lateral Movement',
    },
    'rdp': {
        'id': 'T1021.001',
        'name': 'Remote Desktop Protocol',
        'tactic': 'Lateral Movement',
    },
    'winrm': {
        'id': 'T1021.006',
        'name': 'Windows Remote Management',
        'tactic': 'Lateral Movement',
    },
    'ssh lateral': {
        'id': 'T1021.004',
        'name': 'SSH',
        'tactic': 'Lateral Movement',
    },
    'pass-the-hash': {
        'id': 'T1550.002',
        'name': 'Pass the Hash',
        'tactic': 'Lateral Movement',
    },
    'pass the hash': {
        'id': 'T1550.002',
        'name': 'Pass the Hash',
        'tactic': 'Lateral Movement',
    },
    'pass-the-ticket': {
        'id': 'T1550.003',
        'name': 'Pass the Ticket',
        'tactic': 'Lateral Movement',
    },
    'pass the ticket': {
        'id': 'T1550.003',
        'name': 'Pass the Ticket',
        'tactic': 'Lateral Movement',
    },
    'alternate auth': {
        'id': 'T1550',
        'name': 'Use Alternate Authentication Material',
        'tactic': 'Lateral Movement',
    },
    'session hijack': {
        'id': 'T1563',
        'name': 'Remote Service Session Hijacking',
        'tactic': 'Lateral Movement',
    },
    'lateral movement': {
        'id': 'T1021',
        'name': 'Remote Services',
        'tactic': 'Lateral Movement',
    },
    'exploitation of remote': {
        'id': 'T1210',
        'name': 'Exploitation of Remote Services',
        'tactic': 'Lateral Movement',
    },
    'ntlm relay': {
        'id': 'T1187',
        'name': 'Forced Authentication',
        'tactic': 'Lateral Movement',
    },
    'forced authentication': {
        'id': 'T1187',
        'name': 'Forced Authentication',
        'tactic': 'Lateral Movement',
    },

    # --- Collection ---
    'data from local': {
        'id': 'T1005',
        'name': 'Data from Local System',
        'tactic': 'Collection',
    },
    'data from network': {
        'id': 'T1039',
        'name': 'Data from Network Shared Drive',
        'tactic': 'Collection',
    },
    'nfs export': {
        'id': 'T1039',
        'name': 'Data from Network Shared Drive',
        'tactic': 'Collection',
    },
    'iscsi': {
        'id': 'T1039',
        'name': 'Data from Network Shared Drive',
        'tactic': 'Collection',
    },
    'mailbox': {
        'id': 'T1114',
        'name': 'Email Collection',
        'tactic': 'Collection',
    },
    'email access': {
        'id': 'T1114',
        'name': 'Email Collection',
        'tactic': 'Collection',
    },
    'kafka topic': {
        'id': 'T1005',
        'name': 'Data from Local System',
        'tactic': 'Collection',
    },
    'data exfil': {
        'id': 'T1005',
        'name': 'Data from Local System',
        'tactic': 'Collection',
    },
    'clipboard': {
        'id': 'T1115',
        'name': 'Clipboard Data',
        'tactic': 'Collection',
    },
    'screenshot': {
        'id': 'T1113',
        'name': 'Screen Capture',
        'tactic': 'Collection',
    },

    # --- Command and Control ---
    'application layer protocol': {
        'id': 'T1071',
        'name': 'Application Layer Protocol',
        'tactic': 'Command and Control',
    },
    'http c2': {
        'id': 'T1071.001',
        'name': 'Web Protocols',
        'tactic': 'Command and Control',
    },
    'https beacon': {
        'id': 'T1071.001',
        'name': 'Web Protocols',
        'tactic': 'Command and Control',
    },
    'beacon': {
        'id': 'T1071.001',
        'name': 'Web Protocols',
        'tactic': 'Command and Control',
    },
    'dns c2': {
        'id': 'T1071.004',
        'name': 'DNS',
        'tactic': 'Command and Control',
    },
    'non-application layer': {
        'id': 'T1095',
        'name': 'Non-Application Layer Protocol',
        'tactic': 'Command and Control',
    },
    'icmp': {
        'id': 'T1095',
        'name': 'Non-Application Layer Protocol',
        'tactic': 'Command and Control',
    },
    'protocol tunnel': {
        'id': 'T1572',
        'name': 'Protocol Tunneling',
        'tactic': 'Command and Control',
    },
    'ssh tunnel': {
        'id': 'T1572',
        'name': 'Protocol Tunneling',
        'tactic': 'Command and Control',
    },
    'websocket': {
        'id': 'T1071.001',
        'name': 'Web Protocols',
        'tactic': 'Command and Control',
    },
    'web shell': {
        'id': 'T1505.003',
        'name': 'Web Shell',
        'tactic': 'Command and Control',
    },
    'cobalt strike': {
        'id': 'T1071.001',
        'name': 'Web Protocols',
        'tactic': 'Command and Control',
    },
    'c2 channel': {
        'id': 'T1071',
        'name': 'Application Layer Protocol',
        'tactic': 'Command and Control',
    },
    'rat': {
        'id': 'T1219',
        'name': 'Remote Access Software',
        'tactic': 'Command and Control',
    },
    'remote access': {
        'id': 'T1219',
        'name': 'Remote Access Software',
        'tactic': 'Command and Control',
    },

    # --- Exfiltration ---
    'exfil over c2': {
        'id': 'T1041',
        'name': 'Exfiltration Over C2 Channel',
        'tactic': 'Exfiltration',
    },
    'exfil over alternative': {
        'id': 'T1048',
        'name': 'Exfiltration Over Alternative Protocol',
        'tactic': 'Exfiltration',
    },
    'exfiltration': {
        'id': 'T1041',
        'name': 'Exfiltration Over C2 Channel',
        'tactic': 'Exfiltration',
    },
    'data theft': {
        'id': 'T1041',
        'name': 'Exfiltration Over C2 Channel',
        'tactic': 'Exfiltration',
    },
    'graph api': {
        'id': 'T1048',
        'name': 'Exfiltration Over Alternative Protocol',
        'tactic': 'Exfiltration',
    },

    # --- Impact ---
    'ransomware': {
        'id': 'T1486',
        'name': 'Data Encrypted for Impact',
        'tactic': 'Impact',
    },
    'data encrypted': {
        'id': 'T1486',
        'name': 'Data Encrypted for Impact',
        'tactic': 'Impact',
    },
    'service stop': {
        'id': 'T1489',
        'name': 'Service Stop',
        'tactic': 'Impact',
    },
    'wiper': {
        'id': 'T1485',
        'name': 'Data Destruction',
        'tactic': 'Impact',
    },
    'data destruct': {
        'id': 'T1485',
        'name': 'Data Destruction',
        'tactic': 'Impact',
    },
    'defacement': {
        'id': 'T1491',
        'name': 'Defacement',
        'tactic': 'Impact',
    },
}


def tag_finding(finding: dict) -> dict:
    """
    Given a finding dict with 'type' and 'description' keys, return a copy
    with 'attck_techniques' list added.

    Each entry in attck_techniques: {'id': 'Txxxx', 'name': str, 'tactic': str}
    Multiple matches are included; duplicates (same technique id) are deduplicated.
    """
    result = dict(finding)

    search_text = ' '.join([
        str(finding.get('type', '')).lower(),
        str(finding.get('description', '')).lower(),
    ])

    seen_ids = set()
    techniques = []

    for keyword, technique in ATTCK_MAP.items():
        if keyword in search_text:
            tid = technique['id']
            if tid not in seen_ids:
                seen_ids.add(tid)
                techniques.append({
                    'id': tid,
                    'name': technique['name'],
                    'tactic': technique['tactic'],
                })

    # Sort by tactic kill-chain order
    tactic_idx = {t: i for i, t in enumerate(TACTIC_ORDER)}
    techniques.sort(key=lambda t: tactic_idx.get(t['tactic'], 99))

    result['attck_techniques'] = techniques
    return result


def tag_findings_list(findings: list) -> list:
    """Map tag_finding over a list of finding dicts."""
    return [tag_finding(f) for f in findings]


if __name__ == '__main__':
    # Self-test
    sample = [
        {'type': 'ASLR Disabled', 'severity': 'HIGH',
         'description': 'Address Space Layout Randomization is disabled'},
        {'type': 'Docker: Privileged Container', 'severity': 'CRITICAL',
         'description': 'Container running with --privileged flag, container escape possible'},
        {'type': 'Credential: shadow', 'severity': 'HIGH',
         'description': '/etc/shadow readable — credential dump risk'},
        {'type': 'SSH private key exposed', 'severity': 'HIGH',
         'description': '/root/.ssh/id_rsa — SSH lateral movement to any host in known_hosts'},
        {'type': 'FLINK_UNAUTH_RCE', 'severity': 'CRITICAL',
         'description': 'Flink 10.0.0.1:8081 JAR upload unauthenticated — RCE'},
        {'type': 'KAFKA_UNAUTH_TOPIC_LIST', 'severity': 'HIGH',
         'description': 'Kafka 10.0.0.1:9092 unauthenticated: 42 topics data exfil risk'},
        {'type': 'CISCO_APIC_DEFAULT_CREDS', 'severity': 'CRITICAL',
         'description': 'apic on 10.0.0.1 — default creds: admin:C1sco12345'},
        {'type': 'API token: aws', 'severity': 'CRITICAL',
         'description': '/home/user/.aws/credentials — cloud control plane access'},
    ]
    tagged = tag_findings_list(sample)
    import json
    print(json.dumps(tagged, indent=2))
