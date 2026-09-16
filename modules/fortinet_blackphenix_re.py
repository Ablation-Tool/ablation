"""
BLACKPHENIX (ips-bph-framework) RE: Fortinet internal malware analysis automation
Sources:
  - ips-bph-framework/bph/core/vm.py (VirtualBox control client)
  - ips-bph-framework/agent/vm_manager/vm_manager.py (VirtualBox TCP server; Windows)
  - ips-bph-framework/agent/windows/agent.py (Windows VM guest agent; Python 2)
  - ips-bph-framework/bph/core/configuration.py (Config parser)
  - ips-bph-framework/bph/core/constants.py (Global constants)
Author: Chris Navarrete @ FortiGuard Labs (BlackHat Arsenal 2019)
"""

# ---------------------------------------------------------
# BLACKPHENIX architecture overview
# ---------------------------------------------------------
BLACKPHENIX_ARCH = {
    "id":       "FBPH-ARCH",
    "product":  "BLACKPHENIX -- Fortinet internal malware analysis automation framework",
    "source":   "ips-bph-framework/ (Apache 2.0; public GitHub via FortiGuard Labs)",
    "author":   "Chris Navarrete @ FortiGuard Labs",
    "context":  "BlackHat Arsenal 2019; internal FortiGuard malware analysis pipeline",

    "components": {
        "bph (Linux)":              "Main analysis orchestrator; Python; submits samples to VMs",
        "vm_manager.py (Windows)":  "VirtualBox TCP control server; manages VM start/stop/restore",
        "agent.py (Windows VM)":    "Guest agent in analysis VMs; receives tool execution commands from C&C",
        "Web Controller":           "HTTP API for sample submission and report retrieval",
        "Template Server":          "TCP server sending tool execution templates to Windows agents",
    },

    "analysis_types": {
        "BasicStaticAnalysis":    "Static analysis VM (VBoxManage machineid/snapshotid from config)",
        "BasicDynamicAnalysis":   "Dynamic analysis VM (malware execution with network logging)",
        "AdvancedStaticAnalysis": "Advanced static analysis VM (disassembler, decompiler tools)",
        "AdvancedDynamicAnalysis": "Advanced dynamic analysis VM (debugger, memory dump)",
    },

    "ipc_protocol": {
        "orchestrator->vm_manager": "TCP; pipe-delimited plaintext; cmd|vm_id|snapshot_id|network_id",
        "template_server->agent":   "TCP; Python pickle serialization (CRITICAL: unauthenticated RCE)",
        "agent->web_controller":    "HTTP POST to /bph/report.php; no auth header",
    },
}

# ---------------------------------------------------------
# FBPH-F01: pickle.loads() on unauthenticated TCP data (CRITICAL RCE)
# ---------------------------------------------------------
FBPH_F01_PICKLE_RCE = {
    "id":       "FBPH-F01",
    "product":  "BLACKPHENIX Windows guest agent -- pickle deserialization RCE",
    "severity": "CRITICAL -- unauthenticated pickle RCE on Windows analysis VMs",
    "class":    "Unsafe deserialization of untrusted data via pickle.loads() (CWE-502)",
    "source":   "agent/windows/agent.py:622",

    "code": (
        "class Agent: "
        "  BUFFER_SIZE = 16384 "
        "  def listen(self): "
        "      while True: "
        "          serialized_data = pickle.loads(self._clientsocket.recv(self.BUFFER_SIZE)) "
        "          template_data = box.Box(serialized_data) "
        "          TemplateManager(template_data) "
        "          self.send('ok')"
    ),

    "description": (
        "The Windows guest agent (agent.py) receives data from the BLACKPHENIX template server "
        "via a TCP socket and immediately deserializes it with Python's pickle.loads(). "
        "pickle.loads() can execute arbitrary Python code during deserialization "
        "(via __reduce__ / __reduce_ex__ hooks). "
        "No authentication is performed: "
        "  - Any client that can connect to BPH_TEMPLATE_SERVER_IP:BPH_TEMPLATE_SERVER_PORT "
        "    can send a malicious pickle payload. "
        "  - The agent connects to the template server (agent initiates connection), "
        "    but the server sends back pickle data with zero authentication. "
        "  - A MITM attacker between the template server and the Windows VMs "
        "    sends a crafted pickle payload -> code execution as the agent user inside the VM. "
        "The template server IP/port are passed as sys.argv[1]/sys.argv[2] at agent startup -- "
        "they are configured via the blackphenix.conf file read by BphTemplateServerConfiguration."
    ),

    "sandbox_escape_scenario": (
        "The analysis VMs run live malware samples. "
        "A sophisticated malware sample can fingerprint the BLACKPHENIX environment: "
        "  - VirtualBox guest additions (vboxguest.sys, VBoxService.exe) "
        "  - BLACKPHENIX tool paths (@tool_drive@, remote_tool_path patterns) "
        "  - Agent process name, agent.py script presence in memory "
        "  - Network connections to BPH_TEMPLATE_SERVER_IP "
        "If the malware identifies BLACKPHENIX, it can: "
        "  1. Find the template server IP (from agent.py's socket or process environment). "
        "  2. Connect to the template server port from the analysis VM "
        "     (if the dynamic analysis network is not isolated from the template server). "
        "  3. Send a crafted pickle payload to the TEMPLATE SERVER "
        "     (which the template server forwards to other agent VMs). "
        "  4. Achieve code execution on ALL connected analysis VMs simultaneously. "
        "This is a full sandbox escape that turns a malware analysis infrastructure into a "
        "malware propagation network -- the BLACKPHENIX C&C becomes the malware's C&C."
    ),

    "exploit_payload": (
        "Minimal pickle RCE payload (Python 2; matches agent.py language): "
        "  import pickle, os "
        "  class Exploit(object): "
        "      def __reduce__(self): "
        "          return (os.system, ('calc.exe',)) "
        "  payload = pickle.dumps(Exploit()) "
        "  socket.send(payload) "
        "Agent receives payload, pickle.loads() calls os.system('calc.exe') "
        "with the agent's user permissions."
    ),

    "re_insight": (
        "The 16384-byte BUFFER_SIZE for a single recv() limits the pickle payload size. "
        "Standard reverse shell payloads (meterpreter staged) can fit in this window. "
        "Unstaged payloads (meterpreter_reverse_tcp) exceed 16KB but can use os.execv() "
        "to load a secondary payload from a URL. "
        "The agent uses Python 2 (print statements, urllib2, base64.decodestring) -- "
        "Python 2 pickle is more permissive than Python 3; Protocol 2 (Python 2 default) "
        "supports full arbitrary code execution in __reduce__."
    ),
}

# ---------------------------------------------------------
# FBPH-F02: subprocess.call with shell=True + user-controlled tool_args
# ---------------------------------------------------------
FBPH_F02_SHELL_INJECTION = {
    "id":       "FBPH-F02",
    "product":  "BLACKPHENIX Windows guest agent -- shell=True with C&C-controlled arguments",
    "severity": "HIGH -- command injection via C&C-supplied tool_args",
    "class":    "Command injection via subprocess.call with shell=True (CWE-78)",
    "source":   "agent/windows/agent.py:215",

    "code": (
        "def execute_tool(self, **cmd_data): "
        "    tool_abs_path = '\"...\"' "
        "    tool_args = cmd_data['tool_args'] "
        "    cmd = '{} {}'.format(tool_abs_path, tool_args) "
        "    subprocess.call(cmd, shell=True) "
    ),

    "description": (
        "The template data received from the C&C server (via pickle) includes tool_args. "
        "tool_args are passed to subprocess.call(cmd, shell=True) after string formatting. "
        "Any C&C-supplied tool_args can inject shell metacharacters (;&|) to execute "
        "arbitrary Windows commands alongside the intended tool. "
        "Note: since FBPH-F01 (pickle RCE) already provides code execution, "
        "this finding is secondary. However, even without exploiting pickle, "
        "a compromised C&C server or template data could inject commands via tool_args."
    ),
}

# ---------------------------------------------------------
# FBPH-F03: VBoxControl TCP server has no authentication
# ---------------------------------------------------------
FBPH_F03_VBOX_NOAUTH = {
    "id":       "FBPH-F03",
    "product":  "BLACKPHENIX vm_manager.py -- unauthenticated VirtualBox control TCP server",
    "severity": "HIGH -- any host on the network can start/stop/restore analysis VMs",
    "class":    "Missing authentication on network service (CWE-306)",
    "source":   "agent/vm_manager/vm_manager.py:186",

    "code": (
        "def main(): "
        "    s = socket.socket() "
        "    host = sys.argv[1] "
        "    port = int(sys.argv[2]) "
        "    s.bind((host, port)) "
        "    s.listen(1) "
        "    while True: "
        "        client_socket, addr = s.accept()  # NO AUTH "
        "        data = client_socket.recv(512).decode('ascii') "
        "        if re.match(r'restart|restore|start|stop', data): "
        "            data = data.strip().split('|') "
        "            vm_data = {'cmd': data[0], 'vm_id': data[1], "
        "                       'snapshot_id': data[2], 'network_id': data[3]} "
        "            if vm_data['cmd'] == 'start': vbox.start(vm_data) "
        "            elif vm_data['cmd'] == 'stop': vbox.stop(vm_data)"
    ),

    "description": (
        "vm_manager.py runs on the Windows host that hosts the VirtualBox analysis VMs. "
        "It binds a TCP socket on host:port (from sys.argv) and accepts connections. "
        "No authentication: any client that can connect can send VM control commands. "
        "Commands: start, stop, restore, restart. "
        "The vm_id and snapshot_id from the client are passed to VBoxManage.exe. "
        "Impact: "
        "  1. Attacker connects to vm_manager port from within the analysis network. "
        "  2. Sends: 'start|MalwareAnalysisVM|CleanSnapshot|1' "
        "  3. vm_manager starts/restores the analysis VM, disrupting ongoing analysis. "
        "  4. Attacker sends 'stop|...' to kill VMs mid-analysis, preventing malware detection. "
        "This is an analysis evasion mechanism: sophisticated malware that reaches the "
        "vm_manager port can destroy its own analysis environment."
    ),

    "vm_id_vboxmanage": (
        "vm_data['vm_id'] is passed to VBoxManage.exe as a list argument: "
        "  [self.vm_manager, 'showvminfo', vm_id] "
        "Using list form (not shell=True), so no shell injection via vm_id. "
        "However, VBoxManage itself may accept vm_id values that match multiple VMs "
        "if the vm_id is a prefix of the machine name. "
        "The regex match only checks the COMMAND field (restart|restore|start|stop), "
        "not the vm_id or snapshot_id fields -- they pass through unvalidated."
    ),
}

# ---------------------------------------------------------
# FBPH-F04: Infinite recursion in error handling
# ---------------------------------------------------------
FBPH_F04_RECURSION = {
    "id":       "FBPH-F04",
    "product":  "BLACKPHENIX framework -- infinite recursion on connection failure",
    "severity": "LOW -- crash/DoS on persistent connection failure",
    "class":    "Uncontrolled recursion (CWE-674); Python stack overflow",

    "locations": {
        "bph/core/vm.py:__client_connector()":          "Recursive call on socket.error with 5s sleep",
        "agent/windows/agent.py:reconnect()":            "Recursive call on socket.error with RETRY_SECS sleep",
        "agent/vm_manager/vm_manager.py:__is_vm_running()": "Recursive call on 'restoring' VM status",
    },

    "description": (
        "Multiple functions retry by recursion without depth tracking: "
        "  1. BphVmControl.__client_connector(): on socket.error, sleeps 5s and calls itself. "
        "     Python default recursion limit: 1000. After 1000 retry attempts (83+ minutes), "
        "     raises RecursionError and crashes the analysis orchestrator. "
        "  2. Agent.reconnect(): similar pattern, crashes after RETRY_SECS * 1000 seconds. "
        "  3. VBoxControl.__is_vm_running(): if VM is in 'restoring' state, "
        "     sleeps 5s and calls itself. A VM stuck in 'restoring' = infinite recursion. "
        "These are denial-of-service conditions triggered by persistent network failure "
        "or by a VM snapshot restoration hanging."
    ),
}

# ---------------------------------------------------------
# FBPH systemic: sandbox escape via C&C compromise chain
# ---------------------------------------------------------
FBPH_SYSTEMIC = {
    "id":       "FBPH-SYSTEMIC",
    "product":  "BLACKPHENIX -- C&C compromise chain: template server -> all analysis VMs",
    "severity": "CRITICAL -- single C&C compromise -> code execution on all analysis infrastructure",

    "chain": (
        "1. Compromise the BLACKPHENIX template server (or MITM template server <-> agents). "
        "2. Send crafted pickle payload to all connected Windows agents (FBPH-F01). "
        "3. pickle.loads() executes arbitrary code in all analysis VMs simultaneously. "
        "4. Attacker controls all analysis machines -- can: "
        "   (a) Corrupt analysis results (malware samples appear benign). "
        "   (b) Extract all malware samples submitted to BLACKPHENIX. "
        "   (c) Pivot to the host Windows machine via VirtualBox guest escape or VBoxManage API. "
        "   (d) Use the host's network access to reach internal Fortinet infrastructure. "
        "Alternatively (from within a malware sample): "
        "1. Malware fingerprints BLACKPHENIX environment. "
        "2. Malware finds template server address from agent.py socket. "
        "3. Malware sends malicious pickle payload to template server. "
        "4. Template server forwards to all connected agents. "
        "5. All analysis VMs compromised."
    ),

    "fortiguard_impact": (
        "BLACKPHENIX is the automated analysis component of FortiGuard Labs. "
        "Compromise of the analysis infrastructure allows: "
        "  - Suppression of malware detection (samples appear benign). "
        "  - Theft of all malware samples submitted by FortiGuard (intelligence loss). "
        "  - Manipulation of IPS signatures generated from analysis output. "
        "  - Access to Fortinet internal network via the analysis host network. "
        "This is a threat intelligence pipeline attack: "
        "compromise BLACKPHENIX = compromise the foundation of FortiGuard's malware research."
    ),
}
