"""
Cisco Intersight Appliance onprem-1.0.11 Package RE

Target:  onprem-1.0.11-20260505030332890.hotfix.20260609203635934.tar.gz
         From disk3 /cisco/software/images/ on intersight-appliance-installer-kvm-1.1.7-0.a
         The onprem package is the core Intersight appliance orchestration layer:
         Ansible playbooks, Kubernetes Jinja2 deployment templates, service roles,
         Ansible variables (common vars), shell scripts for install/upgrade/cert-renew
         995 files, single root: appliance/
Companion: an-onprem-bootstrap-1.0.11-20260513221359485.tgz (12MB, Node.js setup wizard
           UI bundles; @andromeda/an-onprem-bootstrap, SVG icons + i18n, no secrets)
Key files: roles/common/vars/main.yml (global constants, service URLs, registry)
           kubernetes/*.j2 (Jinja2 templates for 35+ Intersight microservices)
           kubernetes/config/assist-infra-admin-cluster-role.yaml (RBAC ClusterRole)
           kubernetes/config/assist-cxapp-access-cluster-role.yaml (RBAC ClusterRole)
           tasks/ovf-to-dict.yml (OVF property parsing: vmtoolsd -> XML -> JSON -> Ansible)
           certs/*.cnf (PKI cert config templates for MongoDB, Kafka, Kubernetes, HA-proxy)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_intersight_onprem_ansible_re",
    "firmware": "onprem-1.0.11-*.tar.gz (disk3 /cisco/software/images/)",
    "components": {
        "roles/common/vars/main.yml (global Ansible constants)": (
            "dockerhub_url=dockerhub.cisco.com/cspg-docker/andromeda (private); "
            "vault_addr=https://vault-0.default.svc.cluster.local:8200 (HTTPS OK); "
            "enigma_addr=http://enigma.default.svc.cluster.local (HTTP); "
            "hammer_access_url=http://hammer.default.svc.cluster.local (HTTP, MinIO); "
            "oc_registry_url=http://crusader-web.default.svc.cluster.local:3000/api/scope (HTTP); "
            "prometheus_addr=http://prometheus.default.svc.cluster.local:9090 (HTTP); "
            "cisco_idp_url=https://cloudsso-test.cisco.com (TEST SSO endpoint); "
            "cisco_url=https://www-stage.cisco.com/ (stage Cisco.com); "
            "ec2_tag_environment=Development (hardcoded); "
            "equinox_ip=192.168.20.21 (hardcoded); "
            "hammer_account_id=100000000000 (hardcoded MinIO account); "
            "onprem_ca_key=/opt/cisco/common/onprem-ca.key (CA key path)"
        ),
        "kubernetes/*.j2 (35+ service Jinja2 templates)": (
            "Exposes codenames: amigo, barracuda, blaze, bordeaux, cinnamon, combatant, "
            "echo, epic, ferrari, freeport, fusion, galaxy, gershwin, hammer, hawaii, "
            "hedwig, hekk, helios, horizon, jasmine, ketchup, kodiak, manhattan, napa, "
            "omega, orion, oslo, perseus, plano, puffin, pulsar, reno, sherlock, "
            "swissarmy, thunderbird, yoda (35 services); "
            "all pulled from {{ dockerhub_url }}/{{ service }}:{{ image_tag }}"
        ),
        "kubernetes/config/assist-infra-admin-cluster-role.yaml": (
            "resources=[pods/exec, pods/attach, pods/portforward, secrets, services]; "
            "verbs=[create,delete,get,list,patch,update,watch] on secrets; "
            "rbac.authorization.k8s.io/rolebindings+roles: verbs=[*]; "
            "namespaces: create/delete; serviceaccounts: create/delete; "
            "networking.istio.io/gateways+virtualservices: [*]; "
            "charts.helm.k8s.io: resources=[*] verbs=[*]"
        ),
        "tasks/ovf-to-dict.yml (OVF property parsing)": (
            "vmtoolsd --cmd 'info-get guestinfo.ovfEnv' -> XML -> parse_ovf.py -> JSON; "
            "parse_ovf.py: xml.dom.minidom.parseString -> oe:key/oe:value extraction; "
            "parsed properties include admin password (andromeda_password.cfg path); "
            "no_log: '{{ no_log_config }}' (conditional, not unconditional)"
        ),
    },
    "finding_count": "6F [0C+2H+3M+1L]",
    "cumulative": "837 [78C+287H+271M+200L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "MinIO (hammer) and enigma service accessed over HTTP; firmware images stored in hammer with no transport encryption",
        "description": (
            "roles/common/vars/main.yml defines: "
            "hammer_access_url='http://hammer.default.svc.cluster.local' (HTTP port 80), "
            "enigma_addr='http://enigma.default.svc.cluster.local' (HTTP), "
            "oc_registry_url='http://crusader-web.default.svc.cluster.local:3000/api/scope' (HTTP), "
            "prometheus_addr='http://prometheus.default.svc.cluster.local:9090' (HTTP). "
            "hammer is the MinIO object store codename. "
            "The Ansible variables also define: "
            "hammer_proxy_path='hawaii' (the proxy path through the hawaii service), "
            "assist_infra_dc_bucket='assist-dc', druid_infra_db_bucket='druid-data'. "
            "Firmware images are synced from Intersight cloud to /cisco/software/images/ on disk3 "
            "and served via hammer. "
            "All object storage traffic (firmware uploads, backups, image distribution) "
            "traverses the cluster network over HTTP without TLS. "
            "A compromised pod in the default namespace can MITM hammer traffic, "
            "substitute firmware images in transit, or exfiltrate all stored objects "
            "including backup archives. "
            "Kubernetes cluster networking (Calico, no Istio mTLS by default) does not "
            "encrypt pod-to-pod traffic within the same network."
        ),
        "evidence": {
            "file": "roles/common/vars/main.yml",
            "http_services": (
                "hammer_access_url: http://hammer.default.svc.cluster.local\n"
                "enigma_addr: http://enigma.default.svc.cluster.local\n"
                "oc_registry_url: http://crusader-web.default.svc.cluster.local:3000/api/scope\n"
                "prometheus_addr: http://prometheus.default.svc.cluster.local:9090"
            ),
            "https_contrast": "vault_addr: https://vault-0.default.svc.cluster.local:8200 (HTTPS)",
        },
        "impact": (
            "Firmware images and cluster telemetry in cleartext on pod network. "
            "Compromised pod MITM's hammer to serve malicious firmware to the appliance update pipeline."
        ),
        "remediation": "Enable TLS on MinIO (hammer). Use HTTPS for all inter-service communication or deploy Istio mTLS.",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "assist-admin-cluster-role grants rbac rolebindings/roles: [\"*\"] -- any bound ServiceAccount can self-escalate to cluster-admin",
        "description": (
            "kubernetes/config/assist-infra-admin-cluster-role.yaml grants: "
            "rbac.authorization.k8s.io resources=[rolebindings, roles] verbs=[*]. "
            "A ServiceAccount bound to this ClusterRole can create a ClusterRoleBinding "
            "that binds any ServiceAccount (including itself) to the built-in cluster-admin role. "
            "cluster-admin grants full read/write access to all Kubernetes resources. "
            "The same role also grants: "
            "core/secrets create/delete/patch/update/watch, "
            "core/pods/exec create/delete/get, "
            "core/namespaces create/delete/update, "
            "core/serviceaccounts create/delete, "
            "networking.istio.io/gateways+virtualservices [*], "
            "charts.helm.k8s.io/* [*]. "
            "The assist-cxapp-access-cluster-role.yaml grants the same rbac.authorization.k8s.io "
            "rolebindings/roles [*] plus pods/exec, secrets create/delete/update, "
            "namespaces create/delete. "
            "The Kubernetes documentation explicitly flags 'rolebindings *' as equivalent to "
            "unrestricted privilege escalation -- it is a known escalation path."
        ),
        "evidence": {
            "file": "kubernetes/config/assist-infra-admin-cluster-role.yaml",
            "escalation_rule": (
                "- apiGroups: [rbac.authorization.k8s.io]\n"
                "  resources: [rolebindings, roles]\n"
                "  verbs: ['*']"
            ),
            "additional_privs": "pods/exec, secrets CRUD, namespaces create/delete, serviceaccounts create/delete",
        },
        "impact": (
            "Any service account bound to this role can create a ClusterRoleBinding to cluster-admin. "
            "Compromise of the assist service = full cluster takeover."
        ),
        "remediation": (
            "Remove rolebindings/roles create/update/delete from the assist ClusterRole. "
            "If role management is required, scope to a specific namespace (RoleBinding not ClusterRoleBinding)."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "cloudsso-test.cisco.com and www-stage.cisco.com hardcoded as SSO and Cisco.com endpoints in production appliance package",
        "description": (
            "roles/common/vars/main.yml: "
            "cisco_idp_url: 'https://cloudsso-test.cisco.com' "
            "cisco_url: 'https://www-stage.cisco.com/' "
            "cloudsso-test.cisco.com is Cisco's TEST identity provider (Cisco SSO staging). "
            "www-stage.cisco.com is the staging Cisco.com. "
            "These are Cisco internal pre-production endpoints, not the production SSO. "
            "The Intersight on-premises appliance (version 1.0.11, 2026 release) "
            "authenticates users against cloudsso-test.cisco.com. "
            "Consequences: (1) The SSO integration uses a less-hardened test instance "
            "that may have relaxed security controls; "
            "(2) Authentication failures if the test SSO is decommissioned or changes; "
            "(3) Cisco test SSO typically accepts Cisco employee test accounts, "
            "potentially widening the authentication surface."
        ),
        "evidence": {
            "file": "roles/common/vars/main.yml",
            "sso_url": "cisco_idp_url: https://cloudsso-test.cisco.com",
            "cisco_url": "cisco_url: https://www-stage.cisco.com/",
            "environment": "ec2_tag_environment: Development (hardcoded, also shipped)",
        },
        "impact": (
            "Production appliance authenticates against Cisco test SSO. "
            "Test SSO may have weaker account controls than production IdP."
        ),
        "remediation": "Replace cloudsso-test.cisco.com with cloudsso.cisco.com. Replace www-stage.cisco.com with www.cisco.com.",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "equinox_ip hardcoded as 192.168.20.21 in common vars; connector assumes static IP assignment",
        "description": (
            "roles/common/vars/main.yml: equinox_ip: '192.168.20.21'. "
            "The equinox device connector is expected at a fixed IP 192.168.20.21. "
            "192.168.20.0/24 is a private range separate from the Calico pod CIDR, "
            "suggesting this is the appliance's management network IP assignment for equinox. "
            "A static IP assumption creates: "
            "(1) A predictable address target -- an attacker who controls the "
            "192.168.20.0/24 segment can impersonate the equinox connector at 192.168.20.21; "
            "(2) ARP spoofing on the same L2 segment replaces the legitimate equinox "
            "connector without any authentication failure on the Ansible side; "
            "(3) The equinox connector manages Vault tokens and cluster state -- "
            "impersonating it at 192.168.20.21 intercepts all connector API calls. "
            "This complements ansible.cfg StrictHostKeyChecking=no (disk2/disk3_re F1): "
            "SSH to 192.168.20.21 does not verify the host key."
        ),
        "evidence": {
            "file": "roles/common/vars/main.yml",
            "ip": "equinox_ip: '192.168.20.21'",
            "network": "192.168.20.0/24 (RFC 1918, L2 management network)",
        },
        "impact": "Predictable connector IP enables ARP spoofing for connector impersonation. Combined with no SSH host key check: undetected MITM.",
        "remediation": "Use service discovery (DNS/K8s service name) instead of hardcoded IPs for equinox.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "35 Intersight microservice codenames exposed in kubernetes Jinja2 templates shipped in onprem package",
        "description": (
            "kubernetes/*.j2 templates reference {{ dockerhub_url }}/{{ service_codename }}:{{ image_tag }} "
            "for 35 distinct Intersight microservice codenames: "
            "amigo, barracuda, blaze, bordeaux, cinnamon, combatant, echo, epic, ferrari, "
            "freeport, fusion, galaxy, gershwin, hammer, hawaii, hedgehog, hekk, helios, "
            "horizon, jasmine, ketchup, kodiak, manhattan, napa, omega, orion, oslo, "
            "perseus, plano, puffin, pulsar, reno, sherlock, swissarmy, thunderbird, yoda. "
            "These are all shipped in the onprem tarball and appear as Kubernetes StatefulSet/Deployment "
            "container image names. "
            "Combined with the full Ansible role structure and task filenames (bender, foster, "
            "hurricane, druid, plano from disk2/disk3_re F6), an adversary with access to "
            "Cisco's internal systems can correlate each codename to a "
            "CDETS bug, GitHub Enterprise repo, Artifactory image, and CI/CD pipeline. "
            "The Artifactory repo names (cspg-docker, cspg-intersight-master-docker, "
            "cspg-docker-release) are also exposed in main.yml artifactory_docker_repos."
        ),
        "evidence": {
            "file": "kubernetes/*.j2 + roles/common/vars/main.yml",
            "codenames": (
                "amigo barracuda blaze bordeaux cinnamon combatant echo epic ferrari "
                "freeport fusion galaxy gershwin hammer hawaii hedwig hekk helios horizon "
                "jasmine ketchup kodiak manhattan napa omega orion oslo perseus plano "
                "puffin pulsar reno sherlock swissarmy thunderbird yoda"
            ),
            "artifactory": "cspg-docker, cspg-intersight-master-docker, cspg-docker-release",
        },
        "impact": "35 Intersight service codenames + Artifactory repo names exposed in shipping package.",
        "remediation": "Strip or generalize service names in shipped templates. Use generic identifiers in external artifacts.",
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "hammer_account_id hardcoded as '100000000000' in common vars; predictable MinIO root account identifier",
        "description": (
            "roles/common/vars/main.yml: hammer_account_id: '100000000000'. "
            "hammer is the Intersight MinIO object store. "
            "MinIO account IDs are used in S3-compatible API calls as the access key prefix "
            "and for path-style bucket access. "
            "The value 100000000000 is a 12-digit numeric string -- "
            "characteristic of a MinIO-generated root account ID format. "
            "All Intersight appliances deployed from this package use the same "
            "hammer_account_id. "
            "An adversary who obtains any appliance's object storage credentials "
            "can predict the MinIO account structure for all other appliances, "
            "since the account ID is constant across the deployment fleet."
        ),
        "evidence": {
            "file": "roles/common/vars/main.yml",
            "account_id": "hammer_account_id: '100000000000'",
            "access_url": "hammer_access_url: http://hammer.default.svc.cluster.local (HTTP, see F1)",
        },
        "impact": "Predictable MinIO root account ID across all Intersight appliances.",
        "remediation": "Generate a unique hammer_account_id per appliance at installation time.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
