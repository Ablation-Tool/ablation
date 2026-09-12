"""
Cisco CWOM (IBM Turbonomic 3.16.0) bin.tar Script Analysis RE

Target:  update64_package-3.16.0.iso -> bin.tar (50MB)
Product: Cisco Workload Optimization Manager 3.16.0 / IBM Turbonomic 8.18.0
OS:      CentOS 9 Stream / Rocky Linux
Files:   configure_timescaledb.sh, onlineUpgrade.sh, t8c-license-service.sh,
         k8s-ip-change.sh, turboclientupgrade.sh, olmInstall.sh
Session: 37
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_cwom_bintar_re",
    "firmware": "update64_package-3.16.0.iso -> bin.tar",
    "components": {
        "configure_timescaledb.sh": (
            "PostgreSQL/TimescaleDB initialization; sets credentials, "
            "pg_hba.conf, listen_addresses"
        ),
        "onlineUpgrade.sh": (
            "Internet-connected upgrade path; downloads online-packages.tar "
            "from download.vmturbo.com and executes turboupgrade.sh"
        ),
        "t8c-license-service.sh": (
            "IBM License Service installer; downloads from GitHub "
            "ibm-licensing-operator releases"
        ),
        "turboclientupgrade.sh": (
            "Client upgrade; kubectl apply of operator_bundle.yaml "
            "with sed-substituted registry value"
        ),
        "olm/subscription.yaml": (
            "OLM Subscription with installPlanApproval: Automatic "
            "and 60-minute registry poll"
        ),
    },
    "finding_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 59, "HIGH": 220, "MEDIUM": 217, "LOW": 190},
    "cumulative_total": 686,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": (
            "Hardcoded PostgreSQL Credential 'vmturbo' for postgres and turbo "
            "Superusers with All-Interface Bind"
        ),
        "component": "configure_timescaledb.sh",
        "evidence": {
            "hardcoded_creds": (
                "# set up password for default user postgres\n"
                "sudo -iu postgres psql -c \"ALTER ROLE postgres WITH PASSWORD 'vmturbo'\"\n"
                "# enable 'turbo' user to access psql on localhost of the appliance\n"
                "sudo -iu postgres psql -c \"CREATE ROLE turbo WITH SUPERUSER CREATEDB "
                "CREATEROLE LOGIN REPLICATION BYPASSRLS PASSWORD 'vmturbo'\""
            ),
            "all_interface_bind": (
                "sudo sed -i \"s/#listen_addresses = 'localhost'/listen_addresses = '*'/g\" "
                "$PG_CONF\n"
                "echo \"host    all    all    0.0.0.0/0    md5\" | sudo tee -a $PG_HBA_CONF\n"
                "echo \"host    all    all    ::/0         md5\" | sudo tee -a $PG_HBA_CONF"
            ),
            "affected_roles": [
                "postgres (superuser, inherits all privileges)",
                "turbo (SUPERUSER CREATEDB CREATEROLE LOGIN REPLICATION BYPASSRLS)",
            ],
            "auth_method": "md5 (not scram-sha-256)",
        },
        "impact": (
            "Every CWOM/Turbonomic deployment sets PostgreSQL superuser password to 'vmturbo' "
            "for both the postgres OS user and the turbo application role. "
            "The turbo role is granted SUPERUSER, REPLICATION, and BYPASSRLS -- "
            "full cluster control including bypassing Row-Level Security policies. "
            "PostgreSQL is configured to listen on all interfaces (listen_addresses='*') "
            "with md5 authentication open to 0.0.0.0/0 and ::/0. "
            "Any host that can reach PostgreSQL port 5432 can authenticate as postgres or "
            "turbo using the credential 'vmturbo', with full superuser rights including "
            "pg_read_server_files, pg_write_server_files, and pg_execute_server_program "
            "which enable OS command execution under the postgres user context."
        ),
        "remediation": (
            "Generate a per-instance random password at first boot using openssl rand. "
            "Restrict listen_addresses to the cluster-internal interface, not '*'. "
            "Restrict pg_hba.conf to specific cluster subnets, not 0.0.0.0/0. "
            "Use scram-sha-256 instead of md5 in pg_hba.conf. "
            "Audit all deployed CWOM instances for access on port 5432 with 'vmturbo'."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": (
            "onlineUpgrade.sh Downloads and Executes Tarball from IBM Server "
            "Without Integrity Verification"
        ),
        "component": "onlineUpgrade.sh",
        "evidence": {
            "download_command": (
                "sudo curl -o /mnt/iso/online-packages.tar "
                "https://download.vmturbo.com/appliance/download/updates/"
                "${turboVersion}/online-packages.tar\n"
                "sudo tar -xvf online-packages.tar\n"
                "/mnt/iso/turboupgrade.sh  # or turboclientupgrade.sh"
            ),
            "no_verification": (
                "No checksum of online-packages.tar before extract. "
                "No GPG signature on the tarball. "
                "No hash comparison against any pinned expected value."
            ),
            "version_input": (
                "turboVersion comes from command-line argument $1 -- "
                "caller-controlled, not fetched from a trusted manifest"
            ),
        },
        "impact": (
            "The online upgrade path downloads a tarball from IBM's download server "
            "and immediately executes the extracted upgrade scripts with sudo. "
            "If DNS for download.vmturbo.com is poisoned, the server is compromised, "
            "or a MITM intercepts the HTTP(S) connection, an attacker can deliver "
            "arbitrary scripts that execute at root privilege level on every CWOM "
            "instance performing an online upgrade. The version string is caller-controlled "
            "and used directly in the URL path, providing no tamper evidence."
        ),
        "remediation": (
            "Fetch a detached GPG or SHA256 manifest from a separate CDN endpoint "
            "before downloading the tarball. Verify the tarball against the manifest "
            "before extracting. Consider using a mutual TLS pinned connection to IBM's "
            "download server, or prefer the ISO-based (offline) upgrade path."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": (
            "t8c-license-service.sh Downloads ibm-licensing-operator from GitHub "
            "Without Checksum Verification"
        ),
        "component": "t8c-license-service.sh",
        "evidence": {
            "download_command": (
                "file_url=\"https://github.com/IBM/ibm-licensing-operator/archive/"
                "refs/tags/${operator_version}.zip\"\n"
                "wget -q \"${file_url}\" -O \"${downloaded_file}\"\n"
                "unzip -o -q \"$downloaded_file\" -d \"$destination_folder\"\n"
                "$KUBECTL apply -f ${src_folder}/config/manager/manager.yaml -n ${licensing_namespace}"
            ),
            "no_hash_pin": (
                "operator_version defaults to '4.2.16'. "
                "GitHub tags are mutable; git tag can be moved to a different commit. "
                "No sha256 or commit hash pin. "
                "No sig verification on the downloaded zip."
            ),
        },
        "impact": (
            "IBM License Service is installed by downloading a GitHub release tag zip "
            "and directly applying the extracted YAML manifests to the cluster. "
            "GitHub release tags are not immutable -- a tag can be deleted and recreated "
            "to point to a different commit without warning. "
            "If the IBM GitHub organization account is compromised or the tag is moved, "
            "malicious operator manifests would be applied to every CWOM cluster running "
            "this script. The applied manifests include ClusterRoleBindings, CRDs, and "
            "operator Deployments running in the ibm-common-services namespace."
        ),
        "remediation": (
            "Pin downloads to a specific commit SHA, not a mutable tag. "
            "Use a signed release artifact (GitHub Releases with attached signature) "
            "and verify the signature before applying. "
            "Prefer the offline install path (--offline) which uses files from the "
            "verified ISO image rather than a live GitHub download."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": (
            "onlineUpgrade.sh Unquoted Proxy Variable Allows curl Argument Injection"
        ),
        "component": "onlineUpgrade.sh",
        "evidence": {
            "code": (
                "read -p \"What is the proxy name or IP and port...\" P_NAME_PORT\n"
                "sudo curl -o /mnt/iso/online-packages.tar "
                "https://download.vmturbo.com/... --proxy $P_NAME_PORT"
            ),
            "unquoted": (
                "$P_NAME_PORT is unquoted -- bash word-splits on whitespace. "
                "Input 'http://proxy:8080 --output /etc/sudoers' becomes two curl arguments: "
                "'--proxy http://proxy:8080' and '--output /etc/sudoers'."
            ),
            "sudo_context": "curl runs as root via sudo, so output target can be any path",
        },
        "impact": (
            "The proxy URL provided by the operator during an online upgrade is passed "
            "unquoted to sudo curl. Word splitting allows injection of additional curl flags "
            "when the input contains whitespace. An operator who can provide the proxy string "
            "(e.g., at a compromised or socially-engineered terminal) can inject "
            "'--output /path/to/file' to write arbitrary content as root, "
            "or '--config /tmp/attacker.conf' to pass arbitrary curl config. "
            "The sudo context means the curl process runs as root."
        ),
        "remediation": (
            "Quote the variable: sudo curl ... --proxy \"$P_NAME_PORT\". "
            "Validate the proxy value against an expected URL pattern before use: "
            "[[ $P_NAME_PORT =~ ^https?://[^[:space:]]+:[0-9]+$ ]]"
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": (
            "OLM Subscription installPlanApproval: Automatic with 60-Minute "
            "Registry Poll Auto-Installs Operator Upgrades Without Admin Approval"
        ),
        "component": "yaml/t8c-client-operator/olm/subscription.yaml",
        "evidence": {
            "subscription_yaml": (
                "apiVersion: operators.coreos.com/v1alpha1\n"
                "kind: Subscription\n"
                "  channel: stable\n"
                "  name: t8c-client-operator\n"
                "  installPlanApproval: Automatic  # auto-install on update"
            ),
            "catalog_source_yaml": (
                "kind: CatalogSource\n"
                "  image: icr.io/cpopen/t8c-client-operator-catalog\n"
                "  updateStrategy:\n"
                "    registryPoll:\n"
                "      interval: 60m  # polls every 60 minutes"
            ),
        },
        "impact": (
            "The t8c-client-operator OLM Subscription is configured with "
            "installPlanApproval: Automatic. OLM polls the catalog source every 60 minutes. "
            "When a new operator version appears in the icr.io/cpopen/t8c-client-operator-catalog "
            "image, OLM automatically creates and approves an InstallPlan without administrator "
            "review. If IBM's registry is compromised or if a malicious image is published "
            "to that catalog, it would automatically propagate to all CWOM clusters "
            "using this subscription within one polling cycle. "
            "This design bypasses change management controls."
        ),
        "remediation": (
            "Change installPlanApproval to Manual. "
            "Implement a review process for operator upgrades before approval. "
            "Consider pinning to a specific version in the subscription spec."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "k8s-ip-change.sh Hard-codes UID 1000 Check for turbo User Validation",
        "component": "k8s-ip-change.sh",
        "evidence": {
            "code": (
                "if [[ $(/usr/bin/id -u) -ne 1000 ]]\n"
                "then\n"
                "  echo 'Not running as turbo user, please become the turbo user'\n"
                "  exit\n"
                "fi"
            ),
            "issue": (
                "UID check (id -u) instead of username check (id -un or id -nu turbo). "
                "Any user provisioned with UID 1000 -- whether or not they are 'turbo' -- "
                "passes the check and proceeds to run kubeadm operations."
            ),
        },
        "impact": (
            "The script intends to ensure it runs as the 'turbo' service account. "
            "However, it checks UID 1000 rather than the username 'turbo'. "
            "On systems where UID 1000 is assigned to a different user "
            "(e.g., a developer account or a container escape to UID 1000), "
            "that user passes the check and gains access to all kubeadm cluster operations "
            "including cert renewal and IP address changes that reconfigure the cluster."
        ),
        "remediation": (
            "Replace UID check with username check: "
            "[[ $(id -un) != 'turbo' ]] && exit 1"
        ),
    },
]


def run_module():
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Firmware: {MODULE_SUMMARY['firmware']}")
    for component, desc in MODULE_SUMMARY["components"].items():
        print(f"  {component}: {desc}")
    counts = MODULE_SUMMARY["finding_counts"]
    print(
        f"Findings: {sum(counts.values())} "
        f"[{counts['CRITICAL']}C/{counts['HIGH']}H/"
        f"{counts['MEDIUM']}M/{counts['LOW']}L]"
    )
    cc = MODULE_SUMMARY["cumulative_counts"]
    print(
        f"Cumulative: {MODULE_SUMMARY['cumulative_total']} "
        f"[{cc['CRITICAL']}C+{cc['HIGH']}H+{cc['MEDIUM']}M+{cc['LOW']}L]"
    )
    print()
    for f in FINDINGS:
        sev = f["severity"]
        print(f"  {f['id']} [{sev}] {f['title']}")
        print(f"    Component: {f['component']}")
        print(f"    Impact: {f['impact'][:120]}...")
        print()


if __name__ == "__main__":
    run_module()
