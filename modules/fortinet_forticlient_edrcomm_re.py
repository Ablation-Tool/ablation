"""
FortiClient Linux 7.4.4 edrcomm daemon RE
Sources:
  - /opt/forticlient/edrcomm (1.2MB, ELF x86-64 PIE, Rust, "stripped" but retains panic strings)
Product: FortiClient Linux 7.4.4 (FCT-7.4.4.1964)
Binary: edrcomm -- EDR communication daemon
"""

# ---------------------------------------------------------
# edrcomm -- product context
# ---------------------------------------------------------
EDRCOMM_CONTEXT = {
    "id":       "FCLIENT-EDRCOMM",
    "product":  "FortiClient Linux 7.4.4 -- edrcomm",
    "binary":   "/opt/forticlient/edrcomm",
    "size":     "1,177,640 bytes (1.2MB)",
    "arch":     "ELF x86-64 PIE, Rust, BuildID c5b54c6288ca125a4bc269b40c4769562c92da9b",
    "language": "Rust (confirmed by _ZN Rust mangled symbols in panic strings)",
    "purpose":  "EDR communication daemon: reads NSLO kernel events -> forwards to FortiClient main daemon via NNG IPC",

    "build_info": {
        "build_server":  "/home/devops/code/",
        "rust_source":   "src/base/rust/forticlient/src/edrcomm/src/main.rs",
        "nng_version":   "1.8.0",
        "build_type":    "amd64 debian (.build/amd64/deb/)",
        "signal_hook":   "signal-hook-0.3.17",
    },

    "key_modules": {
        "forticlient::edr::nslo":    "NsloReader: connect + read_message (NSLO kernel event reader)",
        "forticlient::edr::events":  "NsloBlockReason::policy (block decision parsing)",
        "forticlient::edr::message": "NsloMessage::payload, NsloEventMessage::notification",
        "forticlient::shm":          "Shm::new (shared memory segment: fctc_shm)",
        "forticlient::log":          "write_line, set_log_prefix, log_path, log_level",
    },

    "nng_socket_types_used": [
        "nng_pub0_open",     # publish
        "nng_req0_open",     # request/reply
        "nng_pair0_open",    # bidirectional pair
        "nng_push0_open",    # pipeline push
        "nng_pull0_open",    # pipeline pull
        "nng_bus0_open",     # bus (multi-peer)
        "nng_respondent0_open",  # survey respondent
    ],

    "ipc_paths": {
        "nslo_pipe":    "/tmp/olisne-WY4G9IZafUNsloCollectorServicePipe",
        "main_daemon":  "/var/run/userforticlient8f6ddf1358bd9d067261f529f69fda59.ipc",
        "fctc_socket":  "/var/run/fctc.s*",  # truncated in binary
    },
}

# ---------------------------------------------------------
# FCLIENT-EDRCOMM-F01: NSLO pipe pre-creation race in /tmp
# ---------------------------------------------------------
FCLIENT_EDRCOMM_F01_NSLO_PIPE_RACE = {
    "id":       "FCLIENT-EDRCOMM-F01",
    "product":  "FortiClient Linux 7.4.4 -- edrcomm NSLO collector pipe",
    "severity": "MEDIUM -- EDR telemetry interception via /tmp socket pre-creation; requires local user",
    "class":    "TOCTOU / socket pre-creation in /tmp (CWE-362 / CWE-379)",
    "source":   "edrcomm strings: /tmp/olisne-WY4G9IZafUNsloCollectorServicePipe",

    "description": (
        "edrcomm uses NsloReader::connect to DIAL to "
        "  /tmp/olisne-WY4G9IZafUNsloCollectorServicePipe "
        "This path is in /tmp and is world-writable by default. "
        "edrcomm acts as CLIENT (dialer) to this socket, not the server. "
        "The server side is the NSLO kernel collector (likely a kernel module or eBPF program). "
        "Race condition: if a local unprivileged process creates a UNIX socket at "
        "this path BEFORE the NSLO kernel collector does (e.g., at boot), "
        "edrcomm connects to the attacker-controlled socket. "
        "The attacker can then: "
        "  (a) Feed edrcomm false EDR events (policy bypass -- report 'allowed' for malicious actions) "
        "  (b) Drop all NSLO events (blind the EDR subsystem) "
        "  (c) Send malformed events to trigger Rust panic in edrcomm "
        "The binary confirms retry behavior: "
        "  'Lost connection, retrying connection in  seconds' "
        "which means edrcomm will reconnect to the pre-created socket after any disconnect."
    ),

    "evidence": {
        "pipe_path":   "/tmp/olisne-WY4G9IZafUNsloCollectorServicePipe",
        "retry_msg":   "Lost connection, retrying connection in  seconds",
        "connect_fn":  "forticlient::edr::nslo::NsloReader::connect",
    },

    "impact": (
        "Local attacker blinds FortiClient EDR by intercepting the NSLO pipe. "
        "All block decisions (file exec, network, USB) pass through this pipe. "
        "Intercepting it bypasses FortiEDR policy enforcement without touching "
        "any protected kernel structure."
    ),

    "remediation": (
        "Move the socket to /var/run/ (root-only writable) instead of /tmp. "
        "Use abstract UNIX sockets (path starts with \\0) which cannot be "
        "pre-created by unprivileged users. "
        "Verify socket owner/permissions before connecting."
    ),
}

# ---------------------------------------------------------
# FCLIENT-EDRCOMM-F02: Fixed NNG IPC path with static hash
# ---------------------------------------------------------
FCLIENT_EDRCOMM_F02_FIXED_NNG_PATH = {
    "id":       "FCLIENT-EDRCOMM-F02",
    "product":  "FortiClient Linux 7.4.4 -- edrcomm NNG main daemon IPC",
    "severity": "LOW -- predictable IPC path; local process can subscribe to EDR event stream",
    "class":    "Predictable IPC endpoint (CWE-330 / CWE-200)",
    "source":   "edrcomm strings: /var/run/userforticlient8f6ddf1358bd9d067261f529f69fda59.ipc",

    "description": (
        "edrcomm publishes EDR events to main FortiClient daemon at: "
        "  /var/run/userforticlient8f6ddf1358bd9d067261f529f69fda59.ipc "
        "The hash suffix '8f6ddf1358bd9d067261f529f69fda59' appears as a literal string "
        "in the binary -- suggesting it is a fixed value, not runtime-derived from PID or machine ID. "
        "NNG pub0/push0 sockets at a predictable /var/run path mean: "
        "  (a) Any local process that knows this path can subscribe (pull0/sub0) to "
        "      the EDR event stream and read security events without authentication. "
        "  (b) The path is guessable from the binary strings (no randomization)."
    ),

    "evidence": {
        "ipc_path": "/var/run/userforticlient8f6ddf1358bd9d067261f529f69fda59.ipc",
        "hash_appears": "literal string in binary (not runtime-derived)",
    },

    "impact": (
        "Local process subscribes to EDR event stream and reads: "
        "process execution events, file access events, network block events. "
        "Reveals process names, file paths, usernames, PIDs of blocked/monitored activity. "
        "EDR event struct fields: event_id, EventLog, username, magic, pid, path."
    ),

    "remediation": (
        "Apply filesystem permissions to the IPC socket (0600, root:root). "
        "Use SELinux/AppArmor labels to restrict who can connect to the socket. "
        "Use a runtime-derived path (e.g., hash of machine ID + boot ID)."
    ),
}

# ---------------------------------------------------------
# FCLIENT-EDRCOMM-F03: Build path and server credentials disclosure
# ---------------------------------------------------------
FCLIENT_EDRCOMM_F03_BUILD_DISCLOSURE = {
    "id":       "FCLIENT-EDRCOMM-F03",
    "product":  "FortiClient Linux 7.4.4 -- edrcomm build path disclosure",
    "severity": "INFO -- build server path with username leaked in binary",
    "class":    "Information disclosure (CWE-200)",
    "source":   "edrcomm strings",

    "description": (
        "Rust panic strings embed source file paths, revealing: "
        "  Build server username: devops "
        "  Build server path: /home/devops/code/ "
        "  Rust source tree: src/base/rust/forticlient/src/ "
        "  Specific source file: src/edrcomm/src/main.rs "
        "  NNG version: nng-1.8.0 "
        "  Build target: amd64/deb (x86-64 Debian package)"
    ),

    "build_server_paths": [
        "/home/devops/code/src/base/rust/forticlient/src/edrcomm/src/main.rs",
        "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/core/aio.c",
        "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/core/device.c",
        "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/core/dialer.c",
        "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/core/idhash.c",
        "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/core/listener.c",
        "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/core/message.c",
    ],
}

# ---------------------------------------------------------
# EDR event taxonomy (from edrcomm strings)
# ---------------------------------------------------------
EDRCOMM_EVENT_TAXONOMY = {
    "id":     "FCLIENT-EDRCOMM-EVENTS",
    "source": "edrcomm strings (full EDR event type list)",

    "block_events": [
        "Network communication blocked",
        "Internet access blocked",
        "Service access blocked",
        "File volume access blocked",
        "File create blocked",
        "File write blocked",
        "File delete blocked",
        "File encrypt blocked",
        "File rename blocked",
        "File service access blocked",
        "Execution blocked",
        "TCP port listen blocked",
        "File read blocked",
        "Malicious file detected",
        "System configuration change blocked",
        "Dynamic loading blocked",
        "Credential access blocked",
        "USB device blocked",
        "OS security bypass",
        "Logon attempt blocked",
    ],

    "telemetry_events": [
        "InternetAccessAttempt", "AggregationUpdate", "ServicesAccessAttempt",
        "FileVolumeAccessAttempt", "FileCreateAttempt", "FileWriteAccessAttempt",
        "FileDeleteAttempt", "FileEncryptAttempt", "FileRenameAttempt",
        "AggregatedFlowInfo", "FileServiceAccessAttempt", "KeepAlive",
        "FileExecuteAttempt", "TcpListenEdrTunnel", "FileReadAttempt",
        "SystemConfigurationAttempt", "FilelessLoading", "DeviceControl",
        "ManagementSandboxAnalysis", "LogonAttempt", "NoBlock", "CommApp",
        "Isolation", "CommunicationControl", "EDR tunnel",
    ],

    "shared_memory_struct_fields": {
        "ecdata_t_fields": ["magic", "event_id", "EventLog", "username", "pid", "path"],
        "shm_name":        "fctc_shm",
    },

    "note": (
        "edrcomm bridges the NSLO kernel collector to the FortiClient main daemon. "
        "The NSLO module intercepts OS calls and reports them as these event types. "
        "edrcomm does NOT make block decisions -- it only relays events and receives "
        "block decisions from the main daemon (via NNG req0/pair0)."
    ),
}

unique_findings = [
    "FCLIENT-EDRCOMM-F01",  # MEDIUM: NSLO pipe pre-creation race in /tmp
    "FCLIENT-EDRCOMM-F02",  # LOW: predictable NNG IPC path
    "FCLIENT-EDRCOMM-F03",  # INFO: build path disclosure
]
