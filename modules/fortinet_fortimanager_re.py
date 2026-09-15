"""
Fortinet FortiManager FMG_VM64_KVM 8.0.0 RE
Source: FMG_VM64_KVM-v8.0.0.F-build0105-FORTINET.qcow2
Build date: 2026-04-20 | kernel: Linux 6.12.32 (same build as FAZ 8.0.0)
Extraction path: QCOW2 -> virtioa.raw -> P1 (sector 8193, dd) -> /mnt/fmg-p1
Accessible layers: P1 boot partition (ext2), rootfs-ext.tar.xz
Encrypted layers: vmlinuz payload, rootfs.gz (same custom format as FAZ)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":        "Fortinet FortiManager VM64-KVM",
    "os":             "FortiOS 8.0.0.F",
    "build":          "0105",
    "build_date":     "2026-04-20",
    "kernel":         "Linux 6.12.32",
    "kernel_builder": "root@e2770389c733",
    "arch":           "x86-64",

    "image_structure": {
        "qcow2":      "FMG_VM64_KVM-v8.0.0.F-build0105-FORTINET.qcow2",
        "p1_offset":  "sector 8193 (4196352 bytes)",
        "p1_size":    "1GB (2097152 sectors)",
        "p1_files":   ["vmlinuz (5.2MB bzImage)", "rootfs.gz (encrypted)", "rootfs-ext.tar.xz (standard XZ, accessible)"],
    },

    "codebase_identity": {
        "python_app":   "IDENTICAL to FAZ 8.0.0 (md5 differs only in macros.py IMG_TYPE field)",
        "img_type":     "IMG_TYPE = 2 (PRODUCT_FMG); FAZ uses IMG_TYPE = 1 (PRODUCT_FAZ)",
        "rootfs_ext_size": "237MB (vs FAZ's 296MB -- smaller, no FAZ-specific log analytics)",
        "all_ai_code":  "Byte-for-byte identical: agent_views.py, faz_mcp/views.py, mcp.py",
        "agent_definitions": "FMG-SPECIFIC -- entirely different agent set from FAZ (script_agent, dvm_agent, policy_agent, sdwan_diagnose, vpn_diagnose)",
    },

    "apache_modules": {
        "fmg_request.so":    "14KB stripped x86-64; post_read_request hook; queries CMF via libcmdbapi.so, libcmfapi.so; checks Host:127.0.0.1",
        "fmg_rewrite.so":    "76KB stripped x86-64; custom URL rewriter; routes /fdsupdate /FDSService /FCPService /fazproxy /jsonrpc /fgdsvc /workflow /portal",
        "local_mode.so":     "72KB stripped x86-64; implements /Manager /Controller /FirmwareUpgrade handlers; uses libfcpapi.so for FCP package processing",
        "webconsole_module.so": "68KB stripped x86-64; jsonrpc handler; session auth via decrypt_and_auth + session_from_cookie; workflow handler",
    },

    "listen_ports": {
        "443":   "HTTPS main; fmg_rewrite routes; wconsole jsonrpc; ws3 ws://127.0.0.1:9003",
        "80":    "HTTP -> redirect 443; /fdsupdate fct-handler; /fgdsvc fgdsvc-handler",
        "8082":  "HTTPS; ProxyPass -> http://localhost:10745/ (Django AI/MCP server)",
        "26443": "HTTPS management port (same VHost config as 443)",
        "31723": "localhost:31723 internal RPC VHost; same docroot as 443",
    },
}


# ---------------------------------------------------------
# Cross-product findings: all FAZ-F01 through FAZ-F05 apply
# ---------------------------------------------------------

# NOTE: FMG and FAZ 8.0.0 share an identical Python application codebase.
# All findings documented in fortinet_fortianalyzer_re.py apply verbatim to FMG.
# This module records:
# 1. The shared-codebase confirmation
# 2. FMG-specific amplified impact for FAZ-F01
# 3. FMG-specific analysis status

CROSS_PRODUCT_CONFIRMED = {
    "applies_to_fmg": [
        "FAZ-F01: Redis global pub/sub cross-session tool call injection",
        "FAZ-F02: Cookie exposure via webmcpserver cmdline args",
        "FAZ-F03: SSRF via server_url in faz_mcp endpoints (DEBUG-gated)",
        "FAZ-F04: Local MCP server :11345 auth unknown",
        "FAZ-F05: Log search filter passthrough to C daemon",
    ],
    "does_not_apply_to_fmg": {
        "FAZ-F06": "SOAR TLS bypass -- macros.py CONFIG_SOAR=0 in FMG; SOAR connector code present but feature-flagged off",
        "FAZ-F07": "SOAR WEBHOOK SSRF -- same reason; SOAR disabled in FMG",
        "FAZ-F08": "SOAR Redis credential store -- same reason; SOAR disabled in FMG",
        "FAZ-F09": "Apache backend proxy and ClickHouse binary -- APPLIES to FMG (same apache2 config, same ClickHouse binary)",
    },
    "note_agent_definitions_differ": (
        "FAZ agent_definitions and FMG agent_definitions ARE DIFFERENT. "
        "FAZ has: faz_assistant, device_diagnostics, threat_timeline, triage. "
        "FMG has: script_agent, dvm_agent (device_operations, device_config, device_diagnostics), "
        "policy_agent, sdwan_diagnose_root, vpn_diagnose, gui_agents. "
        "FAZ-F01 mechanism (Redis pub/sub) is identical; FMG blast radius covers managed FortiGate fleet."
    ),
    "macros_diff": {
        "IMG_TYPE":       "1 (FAZ) vs 2 (FMG)",
        "CONFIG_PROD_NAME": "FortiAnalyzer-VM64-KVM vs FortiManager-VM64-KVM",
        "CONFIG_SOAR":    "1 (FAZ) vs 0 (FMG)",
        "CONFIG_SIEM":    "1 (FAZ) vs 0 (FMG)",
        "HAVE_UPD_WEBSPAM": "absent (FAZ) vs 1 (FMG)",
        "FAZ_S_DISABLED": "absent (FAZ) vs 0 (FMG -- for enabling FAZ service mode on FMG)",
        "FAZ_S_ENABLED":  "absent (FAZ) vs 1 (FMG)",
    },
    "verification":  "diff -rq of Python trees returns 2 files: _c2pygui.so (binary) and macros.py (above)",
    "reference":     "fortinet_fortianalyzer_re.py",
}


# ---------------------------------------------------------
# FMG-F01: FAZ-F01 with amplified FMG impact
# ---------------------------------------------------------
FMG_F01_REDIS_CROSS_SESSION_AMPLIFIED = {
    "id":       "FMG-F01",
    "product":  "Fortinet FortiManager 8.0.0",
    "severity": "MEDIUM-HIGH -- same as FAZ-F01 but affects managed FortiGate fleet",
    "base":     "FAZ-F01 (fortinet_fortianalyzer_re.py) -- identical code, amplified blast radius",

    "description": (
        "FAZ-F01 Redis global pub/sub injection applies to FMG. "
        "On FMG, the advanced toolsets (general_network_diagnostic, vpn_diagnostic, "
        "sdwan_diagnostic, routing_diagnostic, utilities) execute diagnostic commands "
        "on MANAGED FORTIGATE DEVICES via the MCP server at :11345. "
        "An authenticated user who can inject a tool call response into another user's "
        "agent session could influence operations that run diagnostics on the managed fleet."
    ),

    "amplified_surface": {
        "managed_devices": "FMG manages fleet of FortiGate devices",
        "agent_tools":     "device_diagnostics_agent has tools that run remote device diagnostics",
        "fmg_toolsets":    [
            "fmg://agents/toolsets/advanced/general_network_diagnostic",
            "fmg://agents/toolsets/advanced/vpn_diagnostic",
            "fmg://agents/toolsets/advanced/sdwan_diagnostic",
            "fmg://agents/toolsets/advanced/routing_diagnostic",
            "fmg://agents/toolsets/advanced/utilities",
            "fmg://agents/toolsets/dvm",
            "fmg://agents/toolsets/dvm_config",
            "fmg://agents/toolsets/dvm_diagnose",
        ],
        "high_impact_tools": [
            "schedule_firmware_upgrade (device_operations_agent) -- upgrades firmware on managed FortiGates",
            "install_to_device (device_config_agent) -- pushes config changes to managed FortiGates",
            "modify_configuration (device_config_agent) -- modifies FortiGate device configs",
        ],
        "cross_device_impact": (
            "Tool call injection into a device_operations_agent session could trigger "
            "schedule_firmware_upgrade to downgrade fleet to a vulnerable firmware version. "
            "Injection into device_config_agent could push malicious config changes fleet-wide."
        ),
    },
}


# ---------------------------------------------------------
# FMG-F02: script_agent prompt injection -> fleet-wide CLI execution
# ---------------------------------------------------------
FMG_F02_SCRIPT_AGENT_PROMPT_INJECTION = {
    "id":       "FMG-F02",
    "product":  "Fortinet FortiManager 8.0.0",
    "severity": "HIGH -- LLM prompt injection via script_agent; generated scripts installed on managed FortiGate fleet",
    "file":     "usr/local/lib/python3.11/proj/ai/agent/agent_definitions/script_agent/generate_script.py",

    "description": (
        "The FMG script_agent embeds the user's raw query into LLM system prompts with no sanitization. "
        "The generated FortiGate CLI or Jinja script is sent to the GUI and can be saved and then "
        "installed on managed FortiGate devices via the device_config_agent install_to_device tool. "
        "The risk analyzer is informational only (returns a summary text, no blocking gate). "
        "An attacker with ADMINPRIV_DEV_MANAGER + ADMINPRIV_SCRIPT_ACCESS can craft a prompt "
        "that induces the LLM to generate a malicious CLI script, bypassing the script editor UI."
    ),

    "code_evidence": {
        "injection_point_1": (
            "generate_script.py:try_to_generate_script(): "
            "initial_prompt includes '{args[\"query\"]}' verbatim inside <request> XML tags; "
            "no sanitization, no allowlist of CLI commands"
        ),
        "injection_point_2": (
            "generate_script.py:try_to_generate_script(): "
            "previous_script also injected verbatim into <previous_script> block; "
            "attacker controls prior generated script content via script_id reference"
        ),
        "no_blocking_gate": (
            "script_risk_analyzer.py:analyze_script_risks() called AFTER generation, "
            "returns a text summary; called from agent.py but does NOT gate script delivery; "
            "script reaches GUI regardless of risk summary content"
        ),
        "validate_script_retry": (
            "generate_script.py:try_to_generate_script(): validate_script called via GUI tool; "
            "max 3 retry loops; validation checks syntax only, not content safety"
        ),
    },

    "attack_chain": (
        "1. Authenticate as FMG admin with ADMINPRIV_SCRIPT_ACCESS "
        "2. POST to /run_agent with agent='script_agent' and query containing injection payload "
        "3. LLM generates FortiGate CLI script per injected instructions "
        "4. Script displayed in GUI; attacker clicks save_script "
        "5. Script installed to target FortiGate devices via device_config_agent install_to_device "
        "6. Installed CLI executes on managed devices (e.g. create admin account, open firewall rule)"
    ),

    "agent_registration": {
        "required_permissions": [
            "ADMINPRIV_DEV_MANAGER (11)",
            "ADMINPRIV_SCRIPT_ACCESS (47)",
        ],
        "source": "ai/agent/all_agents.py:ALL_AGENTS_MAP[script_agent]",
    },
}


# ---------------------------------------------------------
# FMG-F03: local_mode.so FCPService -- forged FCP package delivery to managed devices
# ---------------------------------------------------------
FMG_F03_LOCAL_MODE_FCP_FIRMWARE_DELIVERY = {
    "id":       "FMG-F03",
    "product":  "Fortinet FortiManager 8.0.0",
    "severity": "HIGH -- local_mode Apache module processes FCP packages via libfcpapi.so; FCP has CRC32-only integrity (see FAD-F03)",
    "file":     "usr/local/apache2/modules/local_mode.so",

    "description": (
        "The Apache module local_mode.so implements the /Manager, /Controller, and /FirmwareUpgrade "
        "HTTP handlers. It uses libfcpapi.so (FCP_init_request, FCP_recv_request, FCP_unpack_obj_ff, "
        "FCP_pack_obj_ff, FCP_clear_request) to process FCP packages received from managed FortiGate "
        "devices and from FortiGuard. FCP packages have CRC32-only integrity and a hardcoded DES key "
        "(FAD-F03); a forged FCP FIMG (firmware image) or ONCE (run-once executable) package will pass "
        "gpVerifyPkg validation. An authenticated FMG admin can submit forged packages via the "
        "/FirmwareUpgrade endpoint which stores them in /var/fwm/images before distribution to "
        "managed devices."
    ),

    "code_evidence": {
        "fcp_api_calls": [
            "FCP_init_request",
            "FCP_recv_request",
            "FCP_unpack_obj_ff",
            "FCP_clear_request",
            "FCP_pack_obj_ff",
        ],
        "libraries":     ["libfcpapi.so", "libdpmclt.so"],
        "endpoints":     ["/Manager", "/Controller", "/FirmwareUpgrade"],
        "storage_path":  "/var/fwm/images (FMG firmware image store)",
        "dpm_services":  ["dpm_co_service", "dpm_ci_service", "dpm_diff_service", "dpm_list_service"],
        "error_string":  "'unregistered device ignored' -- device registration enforced pre-package delivery",
    },

    "cross_reference": {
        "fcp_integrity": "FAD-F03 -- CRC32-only; DES key S3crtMsG hardcoded at libFCP.so 0x3d90 and VA 0x1a05",
        "fcp_object_types": "FIMG (firmware, idx 18) and ONCE (run-once exec, idx 16) are high-impact delivery targets",
        "routing": "fmg_rewrite.so routes /FCPService -> local_mode.so handler",
    },
}


# ---------------------------------------------------------
# FMG-F04: REDIS_TOOL_CALL_CHANNEL no session binding - cross-session injection
# ---------------------------------------------------------
FMG_F04_TOOL_CALL_CHANNEL_NO_SESSION_BINDING = {
    "id":       "FMG-F04",
    "product":  "Fortinet FortiManager 8.0.0",
    "severity": "MEDIUM -- authenticated cross-session tool call injection; requires tool_call_id (UUIDv4) from target session",
    "file":     "usr/local/lib/python3.11/proj/ai/agent/agent_views.py",

    "description": (
        "The send_tool_call_response view (POST-only, login_required) publishes to the global "
        "REDIS_TOOL_CALL_CHANNEL keyed only by tool_call_id. The listener on the receiving side "
        "matches on tool_call_id UUID with no session binding. Any authenticated FMG user "
        "(regardless of privilege level) can POST to send_tool_call_response with any tool_call_id "
        "and inject a fake result into another user's agent session. The tool_call_id is a UUIDv4 "
        "sent to the browser GUI over WebSocket; exploitation requires observing the target UUID."
    ),

    "code_evidence": {
        "view_handler": (
            "agent_views.py:send_tool_call_response(): "
            "@post_only @login_required -- NO privilege check; "
            "publish_tool_call_resp(tool_call_id=..., result=...) -> REDIS_TOOL_CALL_CHANNEL"
        ),
        "listener_match": (
            "redis_util.py:get_tool_call_result(): "
            "on_message checks 'message[\"tool_call_id\"] == tool_call_id' only; "
            "no session_id, no user_id comparison"
        ),
        "global_channel": (
            "REDIS_TOOL_CALL_CHANNEL is a single global Redis pub/sub channel; "
            "all sessions publish/subscribe to same channel; "
            "ALL authenticated users' tool call traffic is co-mingled"
        ),
    },

    "impact_chain": (
        "1. Victim admin starts device_operations_agent session, triggers schedule_firmware_upgrade "
        "2. Attacker (low-privilege authenticated user) observes tool_call_id from WebSocket traffic "
        "3. Attacker POSTs to /ai/send_tool_call_response with the UUID and malicious result "
        "4. Victim's agent receives attacker's result instead of legitimate GUI response "
        "5. Agent acts on injected result (e.g. confirming a downgrade to vulnerable firmware version)"
    ),

    "additional_unbound_endpoints": {
        "send_tool_call_permission_response": (
            "agent_views.py:820 -- @post_only @login_required; "
            "takes tool_call_id + allowed (bool) + final_jsondata; "
            "publishes to REDIS_TOOL_CALL_PERMISSION_CHANNEL with no session binding; "
            "any auth user can APPROVE another user's pending tool permission (e.g. policy install, config push); "
            "client-side guard 'he.current.has(Ie)' in webclient JS is bypassed by direct HTTP POST"
        ),
        "cancel_tool_call": (
            "agent_views.py:538 -- @post_only @login_required; "
            "takes tool_call_id; calls publish_tool_call_resp(tool_call_id, result='User cancelled the tool call'); "
            "any auth user can cancel ANY running tool call in ANY other user's agent session; "
            "DoS/disruption: cancel a critical remediation action mid-execution"
        ),
        "stop_conversation": (
            "agent_views.py:528 -- @post_only @login_required; "
            "takes request_ids array; calls publish_stop_conversation for each; "
            "any auth user can terminate any running agent conversation by ID; "
            "combined with cancel_tool_call: full disruption of another user's agent session"
        ),
        "run_agent_lock_hold_dos": (
            "agent_views.py:366 -- acquire_redis_lock(get_run_agent_lock(conversation_id), 1); "
            "lock key = conversation_id ONLY (no session_id); "
            "any authenticated user can POST run_agent with victim's conversation_id and hold the lock for the full agent run duration; "
            "victim's concurrent run_agent calls for that conversation_id fail with LockAcquisitionError; "
            "two-stage DoS chain: (1) stop_conversation to kill victim's active run, (2) immediately post run_agent with victim's id to acquire lock and block restart; "
            "note: Redis save/load key does include session_id so attacker cannot read/corrupt victim's conversation data -- DoS only"
        ),
    },

    "attack_surface_summary": (
        "Five endpoints cover the full AI agent lifecycle with only @login_required, no session binding: "
        "(1) send_tool_call_response: inject fake tool result; "
        "(2) send_tool_call_permission_response: approve any pending permission (bypass client guard); "
        "(3) cancel_tool_call: cancel any running tool call; "
        "(4) stop_conversation: terminate any agent session; "
        "(5) any_gui_function_call_resp (FMG-F04/F06): inject result to any GUI tool call. "
        "Together these give any authenticated FMG user complete control over any other user's AI agent session lifecycle."
    ),

    "note_vs_faz_f01": (
        "FAZ-F01 covers the Python-side redis_channel.subscribe injection. "
        "FMG-F04 covers the HTTP-exposed send_tool_call_response endpoint injection. "
        "Both exploit the same global REDIS_TOOL_CALL_CHANNEL; they are complementary paths."
    ),
}


# FMG-F05: VPN diagnose remediation chain -- adversarial device config -> autonomous device fleet modification
# Source: agent_definitions/vpn_diagnose/ (vpn_fixer/agent.py, agent.py, const.py)
# ---------------------------------------------------------
FMG_F05_VPN_DIAGNOSE_ADVERSARIAL_CONFIG = {
    "id":       "FMG-F05",
    "product":  "Fortinet FortiManager (FMG AI agent layer, vpn_diagnose agent)",
    "severity": "HIGH -- adversarial VPN configuration on ONE managed FortiGate can trigger "
                "autonomous script generation and device installation via the vpn_diagnose "
                "remediation chain with no additional user interaction",
    "class":    "Indirect Prompt Injection via Managed Device Config -> Autonomous Device Config Modification",

    "agent_chain": {
        "vpn_diagnose_planner": "Runs 8-step plan: get_phase1_config, get_phase2_config, get_ike_config -> check_if_can_fix() -> remediate_found_issues",
        "check_if_can_fix":     "Called automatically after each of: get_ike_config, get_phase1_config, get_phase2_config, get_underlay_interface_status",
        "multi_agent_consensus": "Spawns 2 parallel issue_finder_agent calls (asyncio.gather) on the DEVICE CONFIG OUTPUT; merges results",
        "issue_finder_agent":   "LLM analyzes raw device config string from get_phase1_config etc.; produces JSON {found_issue: bool, explanation: str}",
        "fixer_agent":          "Instructions: 'IMMEDIATELY use the tool modify_config'; calls modify_config (no user confirmation) then install_to_device (Redis channel, FMG-F04 applicable)",
    },

    "injection_surface": (
        "The VPN diagnostic tools (get_phase1_config, get_phase2_config, get_ike_config) "
        "read configuration directly from the managed FortiGate device and pass the output "
        "as a plain string to check_if_can_fix() -> multi_agent_consensus(). "
        "FortiGate VPN configuration allows arbitrary text in fields: "
        "comments, peer-id, name, description fields. "
        "An attacker with access to configure ONE managed FortiGate device can embed "
        "a prompt injection payload in these fields. When an FMG admin runs VPN diagnose "
        "on the managed device, the payload is passed to the LLM chain. "
        "The issue_finder_agent is instructed to find config issues; a crafted injection "
        "can cause it to report false issues and suggest attacker-controlled 'fixes'."
    ),

    "trigger_condition": (
        "FMG admin initiates 'VPN Diagnose' on the compromised managed FortiGate device. "
        "Plan step 8 ('Remediate Found Issues') automatically calls remediate_found_issues_tool. "
        "No extra user action required beyond running the diagnostic -- step 8 is the final "
        "automated step in the VPN_DIAGNOSE_PLAN_STEPS plan."
    ),

    "fixer_agent_tools": [
        "modify_config -- NO user confirmation step before execution; fixer_agent instructions say 'IMMEDIATELY use the tool'",
        "install_to_device -- same GUI tool channel as FMG-F04; permission check via REDIS_ANY_GUI_FUNCTION_CALL_CHANNEL (no session binding)",
    ],

    "guardrail_coverage": (
        "The protect_instructions_guardrail (FMG-F03 analysis) is NOT applied to tool call results "
        "or device config output (confirmed in FMG_GUARDRAIL_ANALYSIS). "
        "The injection flows through: device config (tool result) -> check_if_can_fix -> "
        "issue_finder_agent initial_prompt -> fixer_agent initial_prompt. "
        "Each sub-agent starts with context.clone(messages=[]) so no system instruction "
        "is present in the sub-agent conversation -- the only content is the attacker-controlled "
        "device config string."
    ),

    "lateral_movement_scope": (
        "fixer_agent instruction: 'Generate one script per device, as needed. Run the install to device tool.' "
        "The 'install_to_device' tool scope is determined by the ADOM policy -- can target all devices "
        "in the ADOM. If the admin runs VPN diagnose from a global ADOM context, the install scope "
        "could be the full managed device fleet."
    ),

    "code_evidence": {
        "check_if_can_fix": "vpn_diagnose/agent.py: called in save_gui_tool_resp_to_context after every CAN_FIX_TOOLS result",
        "fixer_agent_tools": "vpn_diagnose/vpn_fixer/agent.py lines 28-38: tools=[...modify_config or install_to_device...]",
        "fixer_instructions": "vpn_diagnose/vpn_fixer/agent.py lines 15-24: 'IMMEDIATELY use the tool modify_config'; 'run the install to device tool'",
        "plan_step_8": "vpn_diagnose/const.py: step 8 = 'Remediate Found Issues' -> use remediate_found_issues",
    },

    "status": "CONFIRMED -- code path verified; severity depends on injection effectiveness and managed device write access",
}


# FMG-F06: policy_config_agent install_package_to_device + permission approval via unbound Redis channel
# Source: agent_definitions/policy_agent/policy_config_agent.py
# ---------------------------------------------------------
FMG_F06_POLICY_AGENT_INSTALL_SCOPE = {
    "id":       "FMG-F06",
    "product":  "Fortinet FortiManager (FMG AI agent layer, policy_config_agent)",
    "severity": "HIGH -- policy_config_agent exposes install_package_to_device directly in tool set; "
                "permission approval uses REDIS_ANY_GUI_FUNCTION_CALL_CHANNEL with no session binding (FMG-F04); "
                "amplifies FMG-F02 scope from script generation to full policy package installation",
    "class":    "Excessive Tool Privilege + Permission Approval Channel Without Session Binding",

    "tools_with_impact": {
        "create_and_run_script": (
            "Calls send_gui_toolcall_permission_request() before running. "
            "Permission request published to REDIS_ANY_GUI_FUNCTION_CALL_CHANNEL. "
            "FMG-F04 cross-session injection applies: any @login_required user can approve "
            "another user's script execution by injecting a matching response to the channel."
        ),
        "install_package_to_device": (
            "Directly included in policy_config_agent tool set via "
            "gui_assistant_config_to_tools('policy_agent'). "
            "The install step runs after script creation and approval. "
            "This gives the policy_config_agent the complete chain: "
            "generate malicious CLI script + approve via FMG-F04 injection + install to device fleet."
        ),
    },

    "developer_awareness": (
        "policy_config_agent.py bottom comment: "
        "'NOTE: Removed tools due to concerns of sending raw config scripts'. "
        "The commented-out tool is 'get_package_changes_since_last_installation'. "
        "The threat model is aware of raw config script risks but the mitigation "
        "does NOT remove install_package_to_device or address the Redis channel injection. "
        "Fortinet removed a READ-ONLY tool while leaving the execution chain intact."
    ),

    "permission_gate_bypass": (
        "send_gui_toolcall_permission_request() publishes to REDIS_ANY_GUI_FUNCTION_CALL_CHANNEL. "
        "any_gui_function_call_resp endpoint (agent_views.py) is @login_required only; no privilege check; no session binding. "
        "Any authenticated FMG user can publish an 'allowed=true' response to approve another user's "
        "policy installation by racing the GUID-based tool_call_id lookup."
    ),

    "chain_with_fmg_f02": (
        "FMG-F02: user query injected into script_agent -> malicious FortiGate CLI script generated. "
        "FMG-F06: policy_config_agent drives the same script via formal_request (another prompt injection surface) "
        "+ has install_package_to_device to complete the kill chain without requiring script_agent."
    ),

    "code_evidence": {
        "install_in_tool_list": "policy_config_agent.py: gui_assistant_config_to_tools('policy_agent') filtered to include 'install_package_to_device'",
        "permission_channel":   "agent_views.py: any_gui_function_call_resp -> publish_tool_call_resp -> REDIS_ANY_GUI_FUNCTION_CALL_CHANNEL",
        "dev_comment":          "policy_config_agent.py bottom: 'NOTE: Removed tools due to concerns of sending raw config scripts'",
    },

    "status": "CONFIRMED -- tool present in policy_config_agent; channel vulnerability confirmed (FMG-F04)",
}


FMG_F07_VPN_MODIFY_SCRIPT_PROMPT_INJECTION = {
    "id":       "FMG-F07",
    "product":  "Fortinet FortiManager (AI views layer, fmg_vpn_modify_script)",
    "severity": "HIGH -- any authenticated FMG user can inject arbitrary instructions into the VPN CLI script generation LLM; "
                "no privilege check beyond @login_required; no content sanitization; output is FortiGate CLI in JSON format",
    "class":    "Direct Prompt Injection / Insufficient Authorization on AI Generation Endpoint",

    "endpoint":         "POST /p/ai/fmg/vpn/modify_script/",
    "auth_required":    "@post_only @login_required -- no ADOM check, no privilege requirement",
    "injection_point":  "request_body['message'] -> user_prompt passed verbatim as LLM user turn",

    "system_prompt_excerpt": (
        "You are an expert in fortimanager and fortigate CLI scripts. You will be given a set of CLI scripts "
        "and a prompt which will ask you to change something about the scripts. "
        "The scripts are in a json object in the form { [key: script name]: script content, ...} "
        "Generate a new script based on the prompt and return a full json object with the new script "
        "for each script, in the same json object format. Use the same keys as given to name the scripts."
    ),

    "attack_path": (
        "Attacker (any authenticated FMG user) sends POST with message field containing adversarial instructions. "
        "LLM receives raw user input as the user turn with no guardrail (contrast FMG-F03: guardrail not applied here). "
        "AI generates FortiGate CLI script(s) wrapped in JSON, embedding attacker-controlled commands. "
        "If a higher-privilege operator copies the AI output and applies it to managed FortiGate devices, "
        "attacker commands execute on the managed device fleet. "
        "No content validation on the AI response before it is returned to the caller."
    ),

    "distinction_from_f02": (
        "FMG-F02 injects through the script_agent infrastructure (XML-wrapped, goes through guardrail check). "
        "FMG-F07 bypasses agent infrastructure entirely: direct LLM call via send_ai_request('/ai/v1/completions'), "
        "no conversation context, no guardrail, no session context -- pure prompt passthrough."
    ),

    "code_evidence": {
        "file":           "views.py:711-733",
        "injection_line": "user_prompt = request_body['message']  # line 714",
        "model_used":     "AI_MODEL_LARGE (constant, maps to production-grade LLM)",
        "format_json":    "True -- output constrained to JSON format but not sanitized for content",
    },

    "status": "CONFIRMED -- source code; no live device required",
}


FMG_F09_CURRENT_DATAMASK_CROSS_SESSION_LEAK = {
    "id":       "FMG-F09",
    "product":  "Fortinet FortiManager (AI agent views layer, current_datamask endpoint)",
    "severity": "HIGH -- any authenticated FMG user can read any other user's AI conversation datamask "
                "by providing an arbitrary conversation_id; datamask contains original (unmasked) PII: "
                "email addresses, device serial numbers, FortiGate device names submitted to the AI assistant",
    "class":    "Broken Object Level Authorization / Cross-Session Data Exposure",

    "endpoint":         "POST /p/ai/current_datamask/",
    "auth_required":    "@login_required @post_only -- no session ownership validation",
    "redis_key":        "fortiai::datamask::conversation_id:{conversation_id} -- NO session_id in key",

    "vulnerability": (
        "current_datamask reads from Redis using conversation_id ONLY (no session_id). "
        "Any authenticated FMG user can supply any conversation_id and receive the full datamask "
        "for that conversation. The datamask stores the original unmasked values that were "
        "substituted before sending user content to the LLM: email addresses, device serial numbers, "
        "FortiGate device names (CUSTOM_MASK_PREFIX_COLLECTIONS = ['email', 'serial_number', 'fortigate']). "
        "This is a complete bypass of the data masking privacy model -- the attacker recovers the exact "
        "plaintext values the victim was trying to keep private."
    ),

    "authorization_gap_evidence": {
        "missing_check": (
            "current_datamask (agent_views.py:548-567): NO call to get_session_conversation_id(); "
            "reads get_datamask_storage_key(conversation_id) directly from Redis and returns to caller"
        ),
        "properly_protected_endpoints": [
            "submit_datamask (line 575): get_session_conversation_id(request.session_id) == conversation_id check",
            "decrypt_message (line 697): same session ownership check",
            "encrypt_message (line 717): same session ownership check",
            "send_feedback (line 742): same session ownership check",
        ],
        "current_datamask_is_sole_exception": (
            "Every other datamask-related endpoint validates that conversation_id belongs to the requesting session. "
            "current_datamask is the only endpoint that skips this check."
        ),
    },

    "data_exposed": {
        "categories": ["email", "serial_number", "fortigate"],
        "source":     "datamask.py:280 -- CUSTOM_MASK_PREFIX_COLLECTIONS",
        "format":     "full FullDataMask.export() -- collection entries with original and masked values; decrypt map available via get_decrypt_map()",
        "context":    "Any network topology, device inventory, and operator PII that any FMG user typed into the AI assistant is recoverable by another authenticated user who knows (or guesses) the conversation_id",
    },

    "conversation_id_discoverability": (
        "conversation_id is a client-generated UUID stored in the browser; it is transmitted in WebSocket messages "
        "and in all run_agent / create_conversation POST bodies. An attacker on the same network segment monitoring "
        "WebSocket traffic can harvest UUIDs. stop_conversation DoS (FMG-F04) requires the same UUID -- the two findings share the same prerequisite."
    ),

    "code_evidence": {
        "file":          "usr/local/lib/python3.11/proj/ai/agent/agent_views.py:548-567",
        "storage_key":   "datamask.py:229 -- f'fortiai::datamask::conversation_id:{conversation_id}'",
        "return_value":  "JsonResponse(datamask) -- full collection dump including original plaintext values",
    },

    "status": "CONFIRMED -- source code; authorization gap verified against all peer endpoints",
}


FMG_F08_AI_MEDIATED_ENDPOINT_QUARANTINE = {
    "id":       "FMG-F08",
    "product":  "Fortinet FortiAnalyzer (FAZ AI views, faz_assistant tool scope)",
    "severity": "HIGH -- any authenticated FAZ user can cause AI to quarantine any internal managed endpoint "
                "via local_assistant or chat_completions_assistant; action_quarantine_internal_endpoint is "
                "available in both FAZ_FORTIAI_TOOLS and FAZ_FORTIAI_CLEANED_TOOLS with no per-action authorization",
    "class":    "Insufficient Authorization on AI-Accessible Destructive Action / Privilege Escalation via Tool Scope",

    "tools_available_to_any_auth_user": {
        "action_quarantine_internal_endpoint": {
            "parameters":  "ips: array of IPs to quarantine",
            "present_in":  "FAZ_FORTIAI_TOOLS (full set, via chat_completions_assistant) AND FAZ_FORTIAI_CLEANED_TOOLS (restricted set, via local_assistant)",
            "endpoint":    "POST /p/ai/local-assistant/ or POST /p/ai/chat-completions-assistant/",
            "auth":        "@login_required only -- no additional role or privilege check",
            "impact":      "quarantine any internal endpoint managed by FAZ; effective DoS against legitimate hosts",
        },
        "get_system_processes_from_internal_endpoint": {
            "parameters":  "ip or epid (endpoint ID)",
            "present_in":  "FAZ_FORTIAI_CLEANED_TOOLS (faz_assistant.py:803)",
            "endpoint":    "POST /p/ai/local-assistant/",
            "auth":        "@login_required only",
            "impact":      "retrieve running process list from any managed endpoint; information disclosure",
        },
    },

    "attack_path": (
        "Authenticated low-privilege FAZ user sends crafted message to local_assistant: "
        "'Please quarantine host 10.0.0.1 immediately as it appears compromised.' "
        "AI has action_quarantine_internal_endpoint in tool list (FAZ_FORTIAI_CLEANED_TOOLS). "
        "AI returns tool call: {name: 'action_quarantine_internal_endpoint', arguments: {ips: ['10.0.0.1']}}. "
        "Frontend executes the tool call via REDIS_ANY_GUI_FUNCTION_CALL_CHANNEL (or equivalent GUI action channel). "
        "10.0.0.1 is quarantined without any operator confirmation from a higher-privilege account."
    ),

    "tool_execution_model": (
        "action_* tools are GUI function calls -- dispatched via REDIS_ANY_GUI_FUNCTION_CALL_CHANNEL to the FAZ frontend. "
        "A browser session subscribed to the channel executes the action. "
        "Whether a confirmation dialog appears depends on client-side implementation (not confirmed via source). "
        "Even if a dialog is shown, the underlying authorization gap is: a low-privilege user triggered a "
        "quarantine action that should require elevated privilege."
    ),

    "cleaned_tools_misnomer": (
        "FAZ_FORTIAI_CLEANED_TOOLS is used in local_assistant as a 'restricted' tool set "
        "(local LLM, skip_token_check=True, bypass_proxy=True). "
        "It contains action_quarantine_internal_endpoint and get_system_processes_from_internal_endpoint -- "
        "both are destructive/sensitive actions that should require elevated authorization. "
        "The 'cleaned' label implies reduced attack surface; the actual surface includes quarantine capability."
    ),

    "code_evidence": {
        "tool_definition":   "faz_assistant.py:387 (full tools), 859 (cleaned tools)",
        "local_assistant":   "views.py:842-929 -- @post_only @login_required; FAZ path uses FAZ_FORTIAI_CLEANED_TOOLS",
        "chat_completions":  "views.py:736-810 -- @post_only @login_required; FAZ path uses FAZ_FORTIAI_TOOLS (full set)",
        "page_filter_bypass": "get_faz_fortiai_tools filter_by_page=True; page_specific_tools does NOT restrict quarantine -- it is always available",
    },

    "status": "CONFIRMED -- tool scope in source; authorization gap in architecture",
}


# ---------------------------------------------------------
# FMG agent definitions map (unique to FMG, absent in FAZ)
# ---------------------------------------------------------
FMG_AGENT_DEFINITIONS = {
    "script_agent": {
        "permissions": ["ADMINPRIV_DEV_MANAGER (11)", "ADMINPRIV_SCRIPT_ACCESS (47)"],
        "tools": ["generate_script", "modify_script", "save_script", "get_jinja_info", "file_search"],
        "model": "not overridden (inherits session model)",
        "risk_surface": "generates FortiGate CLI scripts; installed on managed devices via device_config_agent",
    },
    "device_operations_agent": {
        "permissions": ["ADMINPRIV_DEV_MANAGER (11)", "ADMINPRIV_DEV_CFG (12)"],
        "tools": ["schedule_firmware_upgrade", "get_device_status", "get_device_licenses", "get_firmware_vulnerability_data", "get_event_logs"],
        "model": "gpt-4.1 (explicit override in device_operations_agent.py)",
        "risk_surface": "firmware upgrade scheduling across managed FortiGate fleet",
    },
    "device_config_agent": {
        "permissions": ["ADMINPRIV_DEV_MANAGER (11)", "ADMINPRIV_DEV_CFG (12)"],
        "tools": ["modify_configuration", "install_to_device", "get_existing_configuration", "get_device_vdoms", "get_interface_datasource"],
        "supported_categories": [
            "config system interface", "config router static", "config system global",
            "config system sdwan", "config system ntp",
            "config vpn ipsec phase1-interface", "config vpn ipsec phase2-interface",
        ],
        "risk_surface": "direct config push and install to managed FortiGate devices",
    },
    "device_diagnostics_agent": {
        "permissions": ["ADMINPRIV_DEV_MANAGER (11)", "ADMINPRIV_DEV_CFG (12)"],
        "mcp_server": "http://127.0.0.1:11345/sse",
        "toolset": "fmg://agents/toolsets/dvm_diagnose + advanced toolsets via tag_map",
        "risk_surface": "executes diagnostic commands on remote FortiGate devices",
    },
    "policy_config_agent": {
        "permissions": ["ADMINPRIV_ADOM_POLICY_PACK (29)", "ADMINPRIV_ADOM_POLICY_OBJECT (30)", "ADMINPRIV_G_POLICY_PACK (6)", "ADMINPRIV_POLICY_OBJECTS (54)"],
        "tools": ["create_and_run_script", "search_for_policy", "show_policies", "get_policy_revision_diff", "install_package_to_device", "navigate_to_policy_package"],
        "mcp_toolset": "fmg://agents/toolsets/policy_management",
        "risk_surface": "ADOM firewall policy modification + install_package_to_device (FMG-F06)",
        "developer_note": "'NOTE: Removed tools due to concerns of sending raw config scripts' -- awareness without fix",
    },
    "vpn_diagnose_planner": {
        "permissions": ["ADMINPRIV_DEV_MANAGER (11)", "ADMINPRIV_DEV_CFG (12)"],
        "tools": ["get_phase1_config", "get_phase2_config", "get_ike_config", "get_vpn_logs_from_fortigate", "get_wan_status_from_fortigate", "get_underlay_interface_status", "modify_config", "remediate_found_issues"],
        "risk_surface": "VPN diagnose reads device config (unfiltered); auto-triggers check_if_can_fix -> fixer_agent (FMG-F05)",
    },
    "fixer_agent": {
        "parent": "vpn_diagnose",
        "tools": ["modify_config", "install_to_device"],
        "instructions_excerpt": "'IMMEDIATELY use the tool modify_config'; 'run the install to device tool'",
        "risk_surface": "no user confirmation for modify_config; install_to_device via FMG-F04 channel",
    },
}


# ---------------------------------------------------------
# FMG guardrail analysis
# ---------------------------------------------------------
FMG_GUARDRAIL_ANALYSIS = {
    "implementation": "ai/agent/util/guardrails/protect_instructions_guardrail.py",
    "model":          "gpt-4.1-mini",
    "type":           "LLM-as-judge: checks if user input is 'very similar' to agent system instructions",
    "bypass":         "Checks similarity to instruction text only; does not detect malicious tool payload injection or adversarial CLI script generation",
    "regex_variant":  "make_protect_instructions_guardrail_by_regex(target_string): regex match on lowercased output; trivial to bypass with case variation or Unicode substitution",
    "not_applied_to": "MCP tool outputs, GUI tool call responses, device config data returned from managed devices",
    "conclusion":     "Guardrail blocks instruction extraction but does not block LLM-generated malicious script content",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "python_layer":   "COMPLETE -- agent_definitions + views.py + faz_mcp/views.py + faz_assistant.py fully analyzed",
    "apache_modules": "COMPLETE -- fmg_request.so, fmg_rewrite.so, local_mode.so, webconsole_module.so analyzed via strings",
    "vmlinuz":        {
        "status":  "BLOCKED -- payload encrypted",
        "version": "Linux 6.12.32 PREEMPT_DYNAMIC (built 2026-04-20 10:50:40 PDT); RO-rootFS",
        "builder": "root@e2770389c733 (different container from FAZ root@49192c769448, same day build)",
    },
    "rootfs_gz":     "BLOCKED -- custom encryption format (same as FAZ, magic 0x5b6758cb...)",
    "rootfs_ext":    "COMPLETE -- 247MB extracted and analyzed; FMG-specific agent surface fully mapped; all HTTP endpoints in ai/urls.py evaluated",
    "syntax_ext":    "ACCESSIBLE -- fmg_cmdb_syntax.json 611KB; not analyzed for injection vectors yet",
    "debug_gates":   "CONFIRMED DISABLED -- SYS.CONFIG_DEBUG hardcoded to 0 in macros.py; faz_mcp/call_tool and debug_1 return 404 in all production builds",
    "webmcpserver":  "BLOCKED -- binary in encrypted rootfs.gz",
    "unique_findings": [
        "FMG-F01: CRITICAL -- FMG-specific amplification of FAZ-F01; script_agent generates and installs scripts on managed device FLEET; REDIS_TOOL_CALL_CHANNEL cross-session injection",
        "FMG-F02: HIGH -- script_agent verbatim query embedding in XML prompt; no content safety check; scripts installable on managed devices via device_config_agent",
        "FMG-F03: MEDIUM -- LLM guardrail (gpt-4.1-mini) checks instruction similarity only; not applied to MCP/tool outputs or device config data",
        "FMG-F04: HIGH -- 5 AI lifecycle endpoints @login_required only, no session binding: send_tool_call_response (inject fake result), send_tool_call_permission_response (approve any pending permission, bypasses client guard), cancel_tool_call (cancel any tool), stop_conversation (terminate any session), any_gui_function_call_resp (inject GUI tool result); full lifecycle control over any user's AI session by any auth FMG user",
        "FMG-F05: HIGH -- vpn_diagnose remediation chain: adversarial VPN config on managed device -> check_if_can_fix (automatic) -> issue_finder_agent -> fixer_agent -> modify_config (no user confirm) + install_to_device; no injection into FMG required",
        "FMG-F06: HIGH -- policy_config_agent includes install_package_to_device in tool set; permission approval via REDIS_ANY_GUI_FUNCTION_CALL_CHANNEL (no session binding); Fortinet developer comment confirms awareness; mitigation removes read-only tool, leaves execution chain intact",
        "FMG-F07: HIGH -- fmg_vpn_modify_script (POST /p/ai/fmg/vpn/modify_script/) passes request_body['message'] verbatim to LLM; @login_required only; no guardrail; any auth user injects adversarial CLI script generation prompt; output applied to managed FortiGate fleet if operator acts on it",
        "FMG-F08: HIGH -- action_quarantine_internal_endpoint in FAZ_FORTIAI_CLEANED_TOOLS; any @login_required FAZ user can cause AI to quarantine any internal endpoint via local_assistant or chat_completions_assistant; get_system_processes_from_internal_endpoint also in cleaned tools; no per-action authorization gate",
        "FMG-F09: HIGH -- current_datamask (POST /p/ai/current_datamask/) has no session ownership check; any @login_required user reads any other user's datamask (original PII values: email, device serial number, FortiGate names) by supplying arbitrary conversation_id; every peer datamask endpoint (submit_datamask, decrypt_message, encrypt_message, send_feedback) validates session ownership -- current_datamask is sole exception; datamask Redis key is conversation_id only (no session_id)",
        "FMG-F04 AMPLIFIED: run_agent lock keyed on conversation_id only; any auth user holds lock for victim's conversation by POSTing to run_agent with victim's id; two-stage DoS: stop_conversation + run_agent lock-hold blocks victim from restarting agent session",
    ],
    "faz_findings_that_apply": ["FAZ-F01", "FAZ-F02", "FAZ-F03", "FAZ-F04", "FAZ-F05", "FAZ-F09"],
}
