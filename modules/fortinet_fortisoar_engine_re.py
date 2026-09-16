"""
FortiSOAR connector engine RE
Sources:
  - fortisoar-connector-engine/connectors/core/ (base_connector.py, connector.py, utils.py, constants.py)
  - fortisoar-connector-engine/connectors/scripts/ (execute_operation.py, generate_sample_playbook.py, capture_output_schema.py)
Products: FortiSOAR (SOAR platform connector plugin system)
"""

# ---------------------------------------------------------
# FortiSOAR connector engine -- product context
# ---------------------------------------------------------
FORTISOAR_CONNECTOR_ENGINE = {
    "id":       "FSOAR-ENGINE",
    "product":  "FortiSOAR connector engine (fortisoar-connector-engine)",
    "source":   "fortisoar-connector-engine/ (Apache 2.0; public GitHub repo)",
    "purpose":  "Plugin framework for FortiSOAR SOAR platform connectors; loads Python connector modules",
}


# ---------------------------------------------------------
# FSOAR-ENGINE-F01: eval() on configparser values in connector tooling
# ---------------------------------------------------------
FSOAR_ENGINE_F01_EVAL = {
    "id":       "FSOAR-ENGINE-F01",
    "product":  "FortiSOAR connector engine -- generate_sample_playbook.py eval() on config values",
    "severity": "MEDIUM -- code execution in connector development tooling; supply chain vector",
    "class":    "eval() on externally-supplied config file values (CWE-95); developer machine compromise",
    "source":   "fortisoar-connector-engine/connectors/scripts/generate_sample_playbook.py",

    "description": (
        "generate_sample_playbook.py reads a .cfg file via configparser and passes values "
        "directly to eval(): "
        "  step_template['description'] = eval(config.get('Alert_Step_Info', 'Alert_Step_Description')) "
        "  step_template['status'] = eval(config.get('Alert_Step_Info', 'Alert_Step_Status')) "
        "  arguments_data['resources'] = eval(config.get('Alert_Step_Info', 'Alert_Step_Source')) "
        "  ... (11+ additional eval() calls on configparser values) "
        "The .cfg file is provided as a command-line argument: --local-data-path. "
        "A malicious FortiSOAR connector package that includes a crafted .cfg file "
        "with Python expressions in the [Alert_Step_Info] or [Connector_Step_Info] sections "
        "achieves arbitrary code execution when a developer runs generate_sample_playbook.py "
        "to generate connector documentation or sample playbooks. "
        "Attack scenario: connector distributed via FortiSOAR Content Hub or GitHub; "
        "developer runs the provided generate_sample_playbook.py workflow; "
        "eval() executes attacker payload (e.g., __import__('os').system('...')). "
        "This is developer tooling, not production FortiSOAR -- the victim is the connector developer."
    ),

    "eval_call_count": "11+ distinct eval() calls on configparser values in generate_sample_playbook.py",

    "re_insight": (
        "The eval() calls appear to exist because the config values can be Python literals "
        "(None, True, False, lists) -- the developer used eval() as a universal deserializer "
        "instead of configparser type-safe accessors or json.loads(). "
        "Safe fix: use ast.literal_eval() (restricts to literal types, no function calls) "
        "or json.loads() for JSON-compatible values. "
        "The existing _convert_verify() function in utils.py already uses ast.literal_eval() correctly -- "
        "the pattern existed in the same codebase but was not applied to the playbook generator."
    ),
}


# ---------------------------------------------------------
# FSOAR-ENGINE-F02: importlib.import_module with user-supplied path (connector supply chain)
# ---------------------------------------------------------
FSOAR_ENGINE_F02_IMPORT = {
    "id":       "FSOAR-ENGINE-F02",
    "product":  "FortiSOAR connector engine -- dynamic module loading without signature verification",
    "severity": "MEDIUM -- any connector Python file is loaded and executed as trusted code",
    "class":    "Unsafe deserialization / arbitrary code execution via plugin loading (CWE-829)",
    "source":   "fortisoar-connector-engine/connectors/scripts/execute_operation.py",

    "description": (
        "get_connector() in execute_operation.py: "
        "  conn_dir = os.path.dirname(connector_path) "
        "  sys.path.append(conn_dir) "
        "  conn_module = importlib.import_module(f'{connector_name}.connector') "
        "The connector directory is added to sys.path and the connector.py is imported. "
        "No code signing, no hash verification, no manifest comparison before import. "
        "Any Python code in {connector_dir}/{connector_name}/connector.py executes at import time. "
        "The FortiSOAR Content Hub distributes thousands of connectors -- "
        "a compromised connector package (supply chain attack) would execute on the FortiSOAR host "
        "when the connector is activated. "
        "FortiSOAR runs as a privileged service; connector code inherits those privileges."
    ),

    "validation_only_checks_path": (
        "validate_input() calls is_path_exist(connector_path) and is_path_exist(local_data_path). "
        "is_path_exist() is a simple os.path.exists() check -- it verifies the path exists "
        "but does not verify the contents of the connector module before import. "
        "Path existence is not equivalent to code integrity verification."
    ),

    "re_insight": (
        "The connector plugin model is intentionally designed for extensibility -- "
        "third-party connectors are a core FortiSOAR feature. "
        "The risk is in the absence of code signing: "
        "FortiSOAR does not verify connector package integrity before loading. "
        "This is the same model used by npm/pip/gem -- the trust assumption is "
        "that packages come from a trusted registry (Content Hub). "
        "A compromised Content Hub or a connector with a malicious dependency "
        "becomes a remote code execution path on every FortiSOAR instance running that connector."
    ),
}


# ---------------------------------------------------------
# FSOAR-ENGINE-F03: TLS verification string conversion in utils.py
# ---------------------------------------------------------
FSOAR_ENGINE_F03_TLS = {
    "id":       "FSOAR-ENGINE-F03",
    "product":  "FortiSOAR connector engine -- _convert_verify() TLS flag handling",
    "severity": "LOW -- verify=False from config string disables TLS verification with no warning",
    "class":    "TLS verification bypass via connector config (CWE-295)",
    "source":   "fortisoar-connector-engine/connectors/core/utils.py",

    "description": (
        "_convert_verify(verify): "
        "  if type(verify) == str and verify: "
        "    try: verify = ast.literal_eval(verify.title()) "
        "    except: logger.warn('Str verification failed.') "
        "  if type(verify) != bool: return True  (safe default) "
        "  return verify. "
        "When a connector configuration sets verify='False' (string): "
        "  verify.title() -> 'False' "
        "  ast.literal_eval('False') -> False "
        "  return False -- TLS verification disabled with no warning to the user. "
        "The connector configuration is typically set by a FortiSOAR admin who may not "
        "understand that verify='False' disables TLS certificate validation. "
        "The warning message 'Str verification failed.' is only logged on conversion error, "
        "not when verify=False is successfully parsed -- no indicator that TLS is disabled."
    ),

    "compare_with_f02_jsonrpc": (
        "Compare FFMG-JSONRPC-F02: JSON-RPC connector also defaults verify_ssl=True in production. "
        "Both connectors share the same TLS bypass path via config string 'False'. "
        "Pattern: FortiSOAR connectors consistently expose TLS bypass via boolean-as-string config values."
    ),
}


# ---------------------------------------------------------
# Systemic: FortiSOAR connector supply chain attack surface
# ---------------------------------------------------------
FORTISOAR_CONNECTOR_SYSTEMIC = {
    "id":       "FSOAR-CONNECTOR-SYSTEMIC",
    "product":  "FortiSOAR (connector ecosystem)",
    "severity": "HIGH -- compromised connector = RCE on FortiSOAR host with FortiSOAR service privileges",

    "pattern": (
        "FortiSOAR's connector ecosystem is a Python plugin framework with no code integrity enforcement. "
        "Three distinct attack paths: "
        "1. Supply chain (Content Hub): malicious connector package -> code execution on FortiSOAR host "
        "   when connector is activated (execute_operation.py import_module). "
        "2. Developer machine: malicious .cfg in connector package -> code execution when developer "
        "   runs generate_sample_playbook.py (11+ eval() calls). "
        "3. Configuration injection: connector config sets verify='False' -> TLS disabled -> "
        "   connector communicates over unauthenticated TLS (allows MITM of connector traffic). "
        "FortiSOAR is deployed at the SOAR layer -- it has authenticated sessions to all integrated "
        "security products (SIEM, firewall, EDR, threat intelligence). "
        "A compromised FortiSOAR connector can pivot to all integrated products simultaneously."
    ),

    "fortinet_soar_position": (
        "FortiSOAR is the integration hub for Fortinet's Security Fabric: "
        "  - FortiGate API access (firewall rule modification) "
        "  - FortiManager access (fleet-wide policy deployment) "
        "  - FortiSIEM integration (alert correlation + response) "
        "  - FortiEDR, FortiNDR, FortiDeceptor integrations. "
        "Persistence via a FortiSOAR connector = persistence at the highest-privilege "
        "orchestration layer of the Fortinet Security Fabric."
    ),
}
