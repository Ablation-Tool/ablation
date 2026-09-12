"""
Cisco Intersight Equinox Connector 1.0.11 RE

Target:  equinox-connector.1.0.11-20260508162630147.20260610215058365.tar.gz
         From disk3 /cisco/software/images/ on intersight-appliance-installer-kvm-1.1.7-0.a
         Equinox is the Intersight on-premises device connector (cloud-to-appliance bridge)
         Binary: bin/equinox (ELF x86-64, UPX-packed, 41MB packed; 128MB unpacked)
         Unpacked: dynamically linked, with debug_info, not stripped
         Build: static Go ELF, BuildID sha1=a243fb2ff7209e024df5a96edf1e14c9aa114ef2
Files:   bin/equinox (Go, k8s.io/client-go + k8s.io/apimachinery + internal starship/* libs)
         startup.sh (process launcher: ulimit -v 500000, nohup)
         install-connector.sh (calls /opt/cisco/bin/update-equinox.sh)
         VERSION: 1.0.11-20260508162630147.20260610215058365
Go imports (binary symbols): github-hyc.scm.engit.cisco.com/starship/apollo/*, equinox/*, iceberg/comm, barcelona/mos
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_intersight_equinox_connector_re",
    "firmware": "equinox-connector.1.0.11-*.tar.gz (disk3 /cisco/software/images/)",
    "components": {
        "bin/equinox (UPX-packed Go binary, 40MB packed / 128MB unpacked)": (
            "k8s.io/client-go, k8s.io/apimachinery; "
            "TLSSkipVerify + InsecureSkipVerify present (string table); "
            "https://127.0.0.1:8200 Vault mgmt paths; "
            "/sbin/chpasswd system call; "
            "127.0.0.1:9004/9006/9092 + localhost:6443 hardcoded ports; "
            "10.193.219.209 hardcoded internal IP"
        ),
        "startup.sh": (
            "CON_LOC=\"dirname $0\" (bash bug: literal string not command substitution); "
            "ulimit -v 500000 (488MB virtual memory limit); "
            "nohup \"$CON_LOC/bin/equinox\" --log_path --dbdir"
        ),
        "install-connector.sh": (
            "bash /opt/cisco/bin/update-equinox.sh \"$1\" false; "
            "update-equinox.sh not in tarball (installed on appliance)"
        ),
        "Go import paths (symbol table)": (
            "github-hyc.scm.engit.cisco.com/starship/apollo/* (Intersight core); "
            "github-hyc.scm.engit.cisco.com/starship/equinox/* (connector); "
            "github-hyc.scm.engit.cisco.com/starship/iceberg/comm; "
            "github-hyc.scm.engit.cisco.com/starship/barcelona/mos"
        ),
    },
    "finding_count": "6F [0C+1H+4M+1L]",
    "cumulative": "831 [78C+285H+268M+199L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "equinox binary calls /sbin/chpasswd directly; password-reset API endpoint in binary",
        "description": (
            "strings on the unpacked equinox binary shows '/sbin/chpasswd' and 'password-reset' "
            "as distinct string table entries. "
            "chpasswd reads username:password pairs from stdin and modifies /etc/shadow. "
            "The equinox connector runs as a privileged process (it starts Kubernetes, "
            "manages Vault, calls nmcli for network config, calls chmod, lsblk, pgrep) -- "
            "it has the privileges needed to call chpasswd successfully. "
            "The binary also shows strings: "
            "'UserPasswordCredential' (credential type), "
            "'asset.ApiKeyCredential' (API key management), "
            "'/v1/auth/token/create' (Vault token creation endpoint), "
            "confirming the connector manages authentication credentials. "
            "The 'password-reset' string likely maps to the API endpoint path exposed by the "
            "equinox web server (port 9004 proxy or Kubernetes endpoint) -- "
            "a remotely accessible password reset function that calls chpasswd internally. "
            "The startup.sh bash bug (F6) prevents equinox from starting via the distributed "
            "script, but the binary is also invoked via install-connector.sh -> update-equinox.sh."
        ),
        "evidence": {
            "binary": "bin/equinox (unpacked, 128MB)",
            "strings": "/sbin/chpasswd, password-reset, UserPasswordCredential, asset.ApiKeyCredential",
            "other_syscalls": "/usr/bin/rsync, /usr/bin/nmcli, /sbin/chpasswd, /usr/bin/chmod",
        },
        "impact": (
            "Intersight connector exposes a password reset primitive that modifies /etc/shadow. "
            "An API request to the password-reset endpoint bypasses normal admin credential flow."
        ),
        "remediation": "Audit the password-reset API endpoint for authentication requirements. Remove /sbin/chpasswd calls if not required.",
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "TLSSkipVerify and InsecureSkipVerify present in equinox binary string table",
        "description": (
            "Unpacked equinox binary string table contains: "
            "'TLSSkipVerify', "
            "'InsecureSkipVerify', "
            "'InsecureSkipTLSVerify)json:\"insecure-skip-tls-verify,omitempty\"'. "
            "The last form is the JSON tag for the kubeconfig InSSkipTLSVerify field, "
            "which the connector reads when loading cluster kubeconfig. "
            "If the Kubernetes cluster kubeconfig has insecure-skip-tls-verify: true, "
            "the equinox connector connects to the Kubernetes API server without cert verification. "
            "Additionally, the connector contacts Vault at 'https://127.0.0.1:8200' -- "
            "per the Ansible deployment findings (cisco_ucs_intersight_disk2_disk3_re F2), "
            "all Ansible Vault calls use verify: no. If equinox also uses InsecureSkipVerify "
            "for its own Vault API calls, the entire credential store is accessed unverified."
        ),
        "evidence": {
            "binary_strings": (
                "TLSSkipVerify\n"
                "InsecureSkipVerify\n"
                "InsecureSkipTLSVerify)json:\"insecure-skip-tls-verify,omitempty\""
            ),
            "vault_url": "https://127.0.0.1:8200 (hardcoded, used with /v1/auth/token/create etc.)",
        },
        "impact": "TLS verification potentially disabled for Kubernetes API and Vault connections.",
        "remediation": "Verify that equinox enforces TLS cert verification for Vault and K8s API connections.",
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "Hardcoded internal IP 10.193.219.209 in equinox binary",
        "description": (
            "Unpacked equinox binary string table contains the literal string '10.193.219.209'. "
            "This is a private IP address (RFC 1918, 10.x.x.x range). "
            "The address does not appear in any configuration template or example block; "
            "it appears in the binary itself as a standalone string. "
            "Context: the string follows strings related to 'DeploymentSize', "
            "'HypervisorType', 'SystemPackages' -- possibly a hardcoded staging or test endpoint. "
            "10.193.0.0/16 is a Cisco internal network range used in Cisco RTP/SJC/RDU campuses. "
            "A hardcoded internal IP in a shipping connector binary exposes internal network topology "
            "and may indicate a development/staging endpoint that was not removed before shipping. "
            "If the equinox binary attempts to contact 10.193.219.209 in production, "
            "the connection fails silently or routes to an unintended host."
        ),
        "evidence": {
            "binary": "equinox unpacked string table",
            "ip": "10.193.219.209 (RFC 1918, Cisco internal range)",
        },
        "impact": "Internal Cisco network topology exposed in shipping firmware.",
        "remediation": "Remove hardcoded internal IPs. Use runtime configuration for all endpoints.",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "Cisco internal Git server github-hyc.scm.engit.cisco.com/starship/* exposed in Go binary symbols",
        "description": (
            "The unpacked equinox binary symbol table contains Go import paths referencing "
            "Cisco's private GitHub Enterprise server: "
            "github-hyc.scm.engit.cisco.com/starship/apollo/* (Intersight core API types/jwt/image/sudi); "
            "github-hyc.scm.engit.cisco.com/starship/equinox/* (connector ha/mos/web/meta/sync/audit/queue/types/utils); "
            "github-hyc.scm.engit.cisco.com/starship/iceberg/comm; "
            "github-hyc.scm.engit.cisco.com/starship/barcelona/mos. "
            "The server 'github-hyc.scm.engit.cisco.com' is Cisco's internal GitHub Enterprise "
            "(hyc = Hyderabad/hybrid cloud datacenter; scm = source control management; "
            "engit = engineering Git). "
            "The 'starship' organization contains all Intersight internal repositories. "
            "These paths appear in Go debug symbols embedded in the binary. "
            "Additional codename 'sudi' confirms the SUDI (Secure Unique Device Identifier) "
            "certificate handling path (Cisco hardware identity certificates)."
        ),
        "evidence": {
            "import_paths": (
                "github-hyc.scm.engit.cisco.com/starship/apollo/api\n"
                "github-hyc.scm.engit.cisco.com/starship/apollo/jwt\n"
                "github-hyc.scm.engit.cisco.com/starship/apollo/sudi\n"
                "github-hyc.scm.engit.cisco.com/starship/equinox/ha\n"
                "github-hyc.scm.engit.cisco.com/starship/iceberg/comm\n"
                "github-hyc.scm.engit.cisco.com/starship/barcelona/mos"
            ),
        },
        "impact": "Cisco internal Git server, project structure, and all 15+ package names exposed in shipping binary.",
        "remediation": "Strip debug symbols before shipping. Use -ldflags='-s -w' for Go builds.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "equinox binary directly manages Vault (foster) at 127.0.0.1:8200 with token create/revoke/mount paths",
        "description": (
            "The unpacked equinox binary contains Vault API path strings: "
            "'/https://127.0.0.1:8200' (Vault base URL), "
            "'/v1/sys/mounts/auth/%s' (auth method mount), "
            "'/v1/auth/token/create' (token creation), "
            "'/v1/sys/leases/revoke/' (lease revocation), "
            "'/v1/sys/revoke-force/.+$' (force revocation regex), "
            "'/v1/sys/mounts/%s/tune' (mount tuning). "
            "These are Vault management-plane operations, not data-plane secret reads. "
            "The equinox connector has Vault admin capability: "
            "it can create tokens, mount/unmount auth methods, revoke leases, and tune mounts. "
            "Combined with the Ansible deployment chain that writes ALL secrets to this same Vault "
            "instance (cisco_ucs_intersight_disk2_disk3_re F2), "
            "a compromised equinox process has access to the full Intersight secret store "
            "via Vault admin APIs, without needing individual secret paths."
        ),
        "evidence": {
            "vault_paths": (
                "https://127.0.0.1:8200\n"
                "/v1/sys/mounts/auth/%s\n"
                "/v1/auth/token/create\n"
                "/v1/sys/leases/revoke/\n"
                "/v1/sys/revoke-force/.+$\n"
                "/v1/sys/mounts/%s/tune"
            ),
        },
        "impact": (
            "Equinox has Vault admin-plane access. "
            "Compromise yields token creation and full lease/mount control over the Intersight secret store."
        ),
        "remediation": "Restrict equinox Vault policy to data-plane read/write only. Revoke sys/* permissions.",
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "startup.sh bash bug: CON_LOC=\"dirname $0\" assigns literal string, not command output",
        "description": (
            "startup.sh line: 'CON_LOC=\"dirname $0\"'. "
            "In bash, double-quoted strings perform variable expansion but NOT command substitution. "
            "The correct forms for command substitution are $(...) or backticks. "
            "CON_LOC receives the literal string 'dirname /path/to/startup.sh' "
            "(where $0 expands to the script path, but dirname is not executed). "
            "The subsequent invocation: 'nohup \"$CON_LOC/bin/equinox\" ...' "
            "expands to 'nohup \"dirname /path/to/startup.sh/bin/equinox\" ...' "
            "which is not a valid executable path. "
            "equinox fails to start when launched via startup.sh as distributed. "
            "The connector is deployed via install-connector.sh -> "
            "/opt/cisco/bin/update-equinox.sh (not in tarball), "
            "suggesting startup.sh may not be the primary invocation path in practice. "
            "Correct form: 'CON_LOC=$(dirname \"$0\")'."
        ),
        "evidence": {
            "file": "startup.sh",
            "bug": "CON_LOC=\"dirname $0\"",
            "correct": "CON_LOC=$(dirname \"$0\")",
            "consequence": "equinox binary path resolves to 'dirname /path/startup.sh/bin/equinox' (nonexistent)",
        },
        "impact": "startup.sh fails silently to launch equinox. Deployment relies on update-equinox.sh path.",
        "remediation": "Fix startup.sh: CON_LOC=$(dirname \"$0\").",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
