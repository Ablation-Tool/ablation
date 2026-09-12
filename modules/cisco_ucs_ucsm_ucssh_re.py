"""
Cisco UCSM 6.0(2b) ucssh.py RE Module
Source: ucs-manager-k9.6.0.2b.bin (inside ucs-6400-k9-bundle-infra.6.0.2b.A.bin)
Component: ucs_manager_plugin.bin inner tar -> ./opt/ucssh.py (16892 bytes)
Deployment path: copied to /ucs/isan/bin/ucssh.py on switch host during container start

ucssh.py is the UCSM container lifecycle management script.
Invoked by exec_sam_upgrade (SUID root) with a JSON params file during upgrade/downgrade.
ParseProcess reads JSON and invokes globals()[param](val)() for each key-value pair.

4 findings: 0C/3H/1M/0L
Cumulative: 645 [55C+209H+200M+181L]
"""

# ============================================================
# UCSSH.PY ARCHITECTURE
# ============================================================

UCSSH_ARCHITECTURE = {
    "purpose": "UCSM container lifecycle management (upgrade/downgrade/restart/migrate)",
    "invocation": {
        "primary": "exec_sam_upgrade (SUID root binary) passes JSON params file path",
        "default_params_file": "/tmp/params_default.json",
        "custom_params": "argv[1] overrides default path",
        "json_dispatch": "ParseProcess reads JSON, calls globals()[key](value)() for each key",
    },
    "classes": [
        "Update (base upgrade class)",
        "SamcProxyUpdate (samcproxy binary upgrade)",
        "RootfsUpdate (LXC container rootfs update)",
        "CoreCollect (core dump collection from switch to SAM)",
        "SamcProxyCoreCollect (samcProxy-specific core filter)",
        "Utils (pmon signal dispatcher)",
        "super (upgrade/downgrade dispatcher -- overrides Python built-in)",
    ],
    "dispatch_mechanism": (
        "ParseProcess(filename).__init__() calls invoke() for each key in JSON. "
        "invoke() calls globals()[param](val)() -- instantiates the Python class named "
        "by the JSON key and immediately calls it. "
        "globals() includes all module-level names. "
        "A crafted JSON file with a key matching any global class name executes that class."
    ),
}

VULNERABLE_CODE_PATHS = {
    "RootfsUpdate_extractTar": {
        "method": "RootfsUpdate.extractTar(aInTarGzFile)",
        "code": 'os.system("/bin/tar zxvf " + aInTarGzFile + " -C " + self.RootFsMountPath + " &> /var/sysmgr/sam_logs/rootfs_extract.log")',
        "source_of_aInTarGzFile": "Passed from RootfsUpdate instance params (JSON input)",
        "injection_type": "os.system string concatenation (no shell=False, no shlex.quote)",
    },
    "super_processCommands_downgrade": {
        "class": "super",
        "code": 'os.system("/isan/bin/tarextract.sh " + self.aInTarGzFile + " " + self.aInExtractPath)',
        "source": "self.aInTarGzFile and self.aInExtractPath from JSON params",
        "injection_type": "os.system string concatenation",
        "note": "Class named 'super' overrides Python built-in; triggered on 'downgrade' command",
    },
    "SamcProxyCoreCollect_shell_true": {
        "method": "SamcProxyCoreCollect.__call__()",
        "code": 'cmd = """ /bin/gzip -cd %s | grep -i %s """ % (os.path.join(self.SwitchCoreDir, fil), samcSign); sp.call(cmd, shell=True, ...)',
        "source": "self.SwitchCoreDir from JSON params",
        "injection_type": "subprocess.call with shell=True, SwitchCoreDir unsanitized",
    },
    "params_file_location": {
        "default_path": "/tmp/params_default.json",
        "directory_permissions": "world-writable (/tmp)",
        "invocation_chain": "exec_sam_upgrade (SUID root) -> ucssh.py -> ParseProcess('/tmp/params_default.json')",
    },
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "UCSM-UCSSH-F1",
        "severity": "HIGH",
        "title": "UCSSH_PARAMS_JSON_IN_WORLD_WRITABLE_TMP_ENABLES_COMMAND_INJECTION_VIA_SUID_EXEC_SAM_UPGRADE",
        "detail": (
            "ucssh.py reads its params from /tmp/params_default.json (world-writable /tmp). "
            "The invocation chain is: exec_sam_upgrade (SUID root, set on every boot per UCSM-SAM-F4) "
            "-> ucssh.py -> ParseProcess('/tmp/params_default.json'). "
            "ParseProcess reads each JSON key and calls globals()[key](value)() to instantiate "
            "the named Python class. Any authenticated local user can pre-create "
            "/tmp/params_default.json with a crafted payload before exec_sam_upgrade runs. "
            "With the JSON key 'RootfsUpdate' pointing to params containing a malicious "
            "RootFsMountPath, or key 'super' with aInTarGzFile='; id; #', the corresponding "
            "class is instantiated and its injected string reaches os.system(). "
            "exec_sam_upgrade is SUID root, so os.system() executes as root. "
            "The race window is the time between exec_sam_upgrade launching and "
            "ParseProcess reading the file; the SUID binary sets up /tmp/params_default.json "
            "itself during upgrade, but a pre-created file (symlink or early write) wins the race. "
            "Source: main() at ucssh.py line ~last, ParseProcess.__init__() via invoke()."
        ),
    },
    {
        "id": "UCSM-UCSSH-F2",
        "severity": "HIGH",
        "title": "ROOTFSUPDATE_EXTRACTTAR_COMMAND_INJECTION_VIA_UNTRUSTED_JSON_PARAM",
        "detail": (
            "RootfsUpdate.extractTar(aInTarGzFile) executes: "
            "os.system('/bin/tar zxvf ' + aInTarGzFile + ' -C ' + self.RootFsMountPath + "
            "' &> /var/sysmgr/sam_logs/rootfs_extract.log') "
            "with no quoting, no shlex.quote(), no sanitization. "
            "Both aInTarGzFile and RootFsMountPath derive from the JSON params file. "
            "A crafted aInTarGzFile value such as '/bootflash/x.tgz; bash -c CMD; #' "
            "injects arbitrary shell commands executing as root (exec_sam_upgrade is SUID). "
            "RootfsUpdate.extractTar() is called from startServices() when rootfs version "
            "mismatch is detected during upgrade. "
            "The same pattern applies to: super.processCommands() downgrade path: "
            "os.system('/isan/bin/tarextract.sh ' + self.aInTarGzFile + ' ' + self.aInExtractPath) "
            "-- both self.aInTarGzFile and self.aInExtractPath come from JSON params without sanitization."
        ),
    },
    {
        "id": "UCSM-UCSSH-F3",
        "severity": "HIGH",
        "title": "PARSEPROCESS_GLOBALS_DISPATCH_EXECUTES_ARBITRARY_PYTHON_CLASS_FROM_JSON_KEY",
        "detail": (
            "ParseProcess.invoke(param, val) calls globals()[param](val)() -- it looks up "
            "the JSON key name in the Python global namespace and instantiates the result as a class. "
            "globals() in Python returns all module-level names including: "
            "builtins, imported modules (os, subprocess, tarfile, sqlite3, xml.etree.ElementTree), "
            "and all class definitions. "
            "A JSON key of 'os' would call os({}).()  which is benign (os is not callable), "
            "but a key of 'SamcProxyCoreCollect' with value {'SwitchCoreDir': '$(cmd>', ...} "
            "instantiates SamcProxyCoreCollect with attacker-controlled params. "
            "The class is immediately called (__call__) after instantiation. "
            "ParseProcess removes the JSON file after processing (os.remove(filename)) "
            "to eliminate forensic evidence. "
            "All class __call__ methods execute with root privilege via exec_sam_upgrade SUID. "
            "Source: ParseProcess.invoke() and main() in ucssh.py."
        ),
    },
    {
        "id": "UCSM-UCSSH-F4",
        "severity": "MEDIUM",
        "title": "SAMCPROXYCORECOLLE CT_SUBPROCESS_SHELL_TRUE_WITH_UNSANITIZED_SWITCHCOREDIR",
        "detail": (
            "SamcProxyCoreCollect.__call__() builds and executes: "
            "cmd = '/bin/gzip -cd %s | grep -i %s' % (os.path.join(self.SwitchCoreDir, fil), samcSign) "
            "then calls subprocess.call(cmd, shell=True, ...). "
            "self.SwitchCoreDir comes from JSON params. "
            "os.path.join() does not prevent directory traversal or shell metacharacters: "
            "SwitchCoreDir = '/var/core; id > /tmp/rce.txt; #' injects a command. "
            "shell=True passes the string to /bin/sh -c, so pipe/semicolon/backtick injection works. "
            "The 'fil' variable comes from os.listdir(self.SwitchCoreDir).endswith('.gz') -- "
            "if SwitchCoreDir is attacker-controlled, os.listdir() on that directory lists "
            "attacker-placed files, further widening the injection surface. "
            "Execution is root via exec_sam_upgrade SUID chain."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_ucsm_ucssh_re",
    "source_file": "./opt/ucssh.py (16892 bytes)",
    "deployment_path": "/ucs/isan/bin/ucssh.py (switch host)",
    "invocation_context": "exec_sam_upgrade SUID root -> ucssh.py -> ParseProcess(JSON)",
    "root_cause": (
        "JSON-driven class dispatch (globals()[key](val)()) combined with "
        "os.system string concatenation (no shlex.quote) and params file in /tmp "
        "(world-writable, SUID invocation chain)"
    ),
    "finding_counts": {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 1, "LOW": 0},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 209, "MEDIUM": 200, "LOW": 181},
    "cumulative_total": 645,
}
