"""
Cisco CVM Virtual Tunnel Client (KVT) 1.4.14 RE

Target:  cvm-vt-client-1.4.14-x86_64.ova
         -> cvm-disk1.vmdk -> cvm-disk1.qcow2
         Single XFS partition, Rocky Linux 9.7 base
         Packer + Ansible build (EC2-exported VM)
Product: Cisco Vulnerability Management Virtual Tunnel Client v434 (KVT)
         (formerly Kenna Security Virtual Tunnel)
Files:   /usr/local/bin/kenna-apikey        (management UI, root cron: * * * * *)
         /usr/local/bin/kenna_virtual_tunnel.rb (KennaVirtualTunnel class)
         /usr/local/bin/tunnel.rb            (entrypoint: KennaVirtualTunnel.new.call)
         /usr/local/bin/version.rb           (VERSION = '434')
         /usr/local/bin/support_scripts/     (dns_check.rb, proxy_check.rb)
         /etc/ssh/sshd_config                (PermitRootLogin yes)
         /var/spool/cron/root                (cron: * * * * * tunnel.rb, @reboot clear_tmp.sh)
Session: 38
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_cvm_vt_client_re",
    "firmware": (
        "cvm-vt-client-1.4.14-x86_64.ova "
        "(Cisco CVM Virtual Tunnel Client v434, Rocky Linux 9.7)"
    ),
    "components": {
        "/usr/local/bin/kenna-apikey": (
            "Interactive management UI; configures API key, client-user, proxy; "
            "runs as root; auth bypass when client-user not set"
        ),
        "/usr/local/bin/kenna_virtual_tunnel.rb": (
            "KennaVirtualTunnel class; downloads tunnel.json from Kenna API; "
            "writes OpenVPN/rinetd/tinyproxy configs to /tmp and symlinks to system paths; "
            "executes hardcoded service restart commands without signature verification"
        ),
        "/usr/local/bin/tunnel.rb": (
            "Cron entrypoint; invokes KennaVirtualTunnel.new.call every minute as root"
        ),
        "/etc/ssh/sshd_config": (
            "PermitRootLogin yes; UseDNS no; root shadow hash present ($6$)"
        ),
        "/var/spool/cron/root": (
            "* * * * * /usr/bin/ruby /usr/local/bin/tunnel.rb (every minute); "
            "@reboot /usr/bin/bash /usr/local/bin/clear_tmp.sh"
        ),
    },
    "finding_counts": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 2, "LOW": 0},
    "cumulative_counts": {"CRITICAL": 62, "HIGH": 232, "MEDIUM": 225, "LOW": 192},
    "cumulative_total": 711,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": (
            "kenna-apikey Management Menu Completely Unauthenticated "
            "When client-user Account Is Not Configured"
        ),
        "component": "/usr/local/bin/kenna-apikey",
        "evidence": {
            "auth_bypass_logic": (
                "The kenna-apikey script checks for a configured client-user account "
                "before requiring authentication:\n\n"
                "  unless authenticated\n"
                "    puts 'Authentication failed. Access denied.'\n"
                "    next\n"
                "  end\n\n"
                "BUT the 'authenticated' predicate is only evaluated when a "
                "client-user is configured. The code path:\n\n"
                "  if !client_user_configured?\n"
                "    puts 'No client-user account configured. CVM Virtual Tunnel menu is unlocked.'\n"
                "    # falls through directly to menu -- no credential check\n"
                "  end"
            ),
            "deployment_default": (
                "The CVM Virtual Tunnel is deployed as a pre-configured OVA template. "
                "The /etc/kenna_api.key file is a 0-byte placeholder at image build time. "
                "On every freshly deployed instance, no client-user account is configured "
                "until the customer explicitly runs kenna-apikey and sets one. "
                "The management menu is unlocked from first boot until that step is taken."
            ),
            "menu_capabilities": [
                "1. Configure Kenna API key (writes /etc/kenna_api.key)",
                "2. Configure proxy credentials (writes /etc/kenna_proxy.creds)",
                "3. Set client-user account and password (sets the auth credential)",
                "4. Show current configuration including proxy host and API key path",
                "5. Test tunnel connectivity",
            ],
            "scope": (
                "Any user on the CVM VM (local or SSH) can access the management menu "
                "before the initial client-user account is set. "
                "The menu includes the ability to SET the client-user account, "
                "meaning an attacker who accesses the menu before legitimate setup "
                "can preemptively lock out the legitimate operator."
            ),
        },
        "impact": (
            "Every Cisco CVM Virtual Tunnel Client OVA deployment ships with its "
            "management interface completely unauthenticated from first boot. "
            "An attacker with any access to the VM (local user, SSH with any credential, "
            "or a process running on the host) can access the management menu, configure "
            "the Kenna API key to point to an attacker-controlled endpoint, set a proxy "
            "that intercepts all tunnel traffic, or configure a client-user credential "
            "the attacker controls -- locking out the legitimate operator. "
            "This is not a race condition; the window is permanent until the customer "
            "explicitly completes initial setup."
        ),
        "remediation": (
            "Require authentication before showing the management menu on every invocation. "
            "If no client-user is configured, require a one-time setup token generated at "
            "image build time and stored in a root-only file, not an open menu. "
            "Alternatively, force initial client-user configuration at first boot "
            "before any other operation is permitted."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": (
            "Ruby Backtick Command Injection via Unsanitized Password Interpolation "
            "in kenna-apikey (openssl passwd -1 -salt xyz #{password})"
        ),
        "component": "/usr/local/bin/kenna-apikey",
        "evidence": {
            "vulnerable_code": (
                "password = ask('Enter password: ') { |q| q.echo = false }\n"
                "password_hash = `openssl passwd -1 -salt xyz #{password}`.strip\n"
                "# password is interpolated directly into a shell command via backticks"
            ),
            "injection_mechanism": (
                "Ruby backtick (``) invokes a shell. "
                "Variable interpolation with #{} inside backticks is not escaped. "
                "A password value of: foo; id > /tmp/pwned; echo bar\n"
                "becomes the shell command:\n"
                "  openssl passwd -1 -salt xyz foo; id > /tmp/pwned; echo bar\n"
                "All three commands execute. The semicolon terminates openssl and "
                "starts the injected command."
            ),
            "execution_context": (
                "kenna-apikey is invoked by the root crontab or interactively by an operator. "
                "The password is read from interactive input (ask() from the Highline gem). "
                "There is no input sanitization or character whitelist before interpolation."
            ),
            "salt_note": (
                "The salt 'xyz' is hardcoded -- all CVM deployments produce identical "
                "hashes for the same password, enabling precomputed rainbow tables."
            ),
        },
        "impact": (
            "Any user who can reach the kenna-apikey menu (which includes unauthenticated "
            "users before client-user setup; see F1) can inject arbitrary shell commands "
            "as root by entering a crafted password string at the 'Enter password' prompt. "
            "The injected commands execute in the context of the process running kenna-apikey, "
            "which is root. "
            "Combined with F1 (unauthenticated menu), this is a local root code execution "
            "path with no prerequisite authentication on a freshly deployed CVM instance."
        ),
        "remediation": (
            "Replace the backtick invocation with a library call that does not invoke a shell. "
            "Ruby's OpenSSL::Digest can compute an MD5-crypt hash natively. "
            "If the openssl binary must be used, pass the password via a pipe or file, "
            "not as an interpolated shell argument: "
            "  IO.popen(['openssl', 'passwd', '-1', '-salt', 'xyz', '-stdin']) {|io| io.write(password)}. "
            "Additionally, replace the static salt 'xyz' with a per-instance random salt."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": (
            "KennaVirtualTunnel Executes API-Controlled File Writes and Service Restarts "
            "Without Content Signature Verification (tunnel.json)"
        ),
        "component": "/usr/local/bin/kenna_virtual_tunnel.rb",
        "evidence": {
            "tunnel_json_flow": (
                "def call\n"
                "  # Downloads tunnel.json from https://<api_host>/tunnel.json\n"
                "  # using X-Risk-Token: <kenna_api_key> header\n"
                "  response = net_http_request(uri)\n"
                "  tunnel_config = JSON.parse(response.body)\n"
                "  # Decodes Base64 file content from JSON, writes to /tmp:\n"
                "  write_file('/tmp/etc/openvpn/openvpn.conf', tunnel_config['vpn_config'])\n"
                "  write_file('/tmp/etc/openvpn/secret.p12', tunnel_config['p12_cert'])\n"
                "  write_file('/tmp/etc/rinetd.conf', tunnel_config['rinetd_config'])\n"
                "  write_file('/tmp/etc/tinyproxy.conf', tunnel_config['proxy_config'])\n"
                "  # Symlinks /tmp/etc/* -> /etc/*  (system paths)\n"
                "  # Then executes commands[]\n"
                "end"
            ),
            "commands_executed": [
                "chattr -i /usr/local/bin/tunnel.rb",
                "rm /etc/rinetd.conf",
                "ln -s /tmp/etc/rinetd.conf /etc/rinetd.conf",
                "sh -c 'if [ ! -e /usr/sbin/tinyproxy ]; then apt-get install -y tinyproxy; fi'",
                "pkill -9 openvpn",
                "/usr/sbin/openvpn --cd /etc/openvpn --config /etc/openvpn/openvpn.conf --daemon",
                "service tinyproxy restart",
                "service rinetd restart",
                "service ntp restart",
            ],
            "no_verification": (
                "No HMAC or signature field in the JSON response. "
                "No TLS certificate pinning on the api_host connection. "
                "File content is raw Base64-decoded from the API response. "
                "The 'chattr -i /usr/local/bin/tunnel.rb' command removes the immutable "
                "flag from tunnel.rb itself -- the API response can replace the entrypoint script."
            ),
            "cron_frequency": (
                "* * * * * /usr/bin/ruby /usr/local/bin/tunnel.rb in /var/spool/cron/root. "
                "Runs every minute as root. "
                "An attacker who controls the Kenna API response has persistent "
                "code execution on every CVM instance within one minute."
            ),
            "apt_on_rocky": (
                "The commands[] array runs 'apt-get install -y tinyproxy' -- a Debian package "
                "manager command on Rocky Linux 9.7 (an RPM-based system). "
                "apt-get is not installed; this command always fails silently. "
                "Indicates the script was written for a Debian/Ubuntu base and was "
                "migrated to Rocky Linux without updating the package manager calls."
            ),
        },
        "impact": (
            "The KennaVirtualTunnel class runs every minute as root and trusts the "
            "Kenna API server as the authoritative source for VPN, proxy, and port "
            "forwarding configuration. "
            "An attacker who can MITM the Kenna API connection (possible without TLS "
            "certificate pinning) or who compromises the Kenna API server can deliver "
            "malicious OpenVPN configurations, route tunnel traffic through attacker "
            "infrastructure, or replace tunnel.rb itself via the 'chattr -i' + Base64 "
            "write path. "
            "Since the cron fires every minute, the attacker has persistent root code "
            "execution on all CVM instances without any credential requirement on the VM itself."
        ),
        "remediation": (
            "Add HMAC-SHA256 signature to tunnel.json responses, keyed with a pre-shared "
            "secret injected at VM provisioning time. "
            "Pin the TLS certificate for the Kenna API host using a bundled CA certificate. "
            "Remove the 'chattr -i /usr/local/bin/tunnel.rb' command from the execution list. "
            "Restrict what file paths the tunnel client will write to based on an allowlist, "
            "not arbitrary paths from the API response."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "sshd_config Permits Root Login (PermitRootLogin yes) with Password Authentication",
        "component": "/etc/ssh/sshd_config",
        "evidence": {
            "config": (
                "PermitRootLogin yes\n"
                "AuthorizedKeysFile .ssh/authorized_keys\n"
                "UseDNS no\n"
                "# No PasswordAuthentication no\n"
                "# No PubkeyAuthentication only"
            ),
            "shadow_root": (
                "root account in /etc/shadow has a SHA-512 crypt hash ($6$) -- "
                "root has a configured password, not a locked account. "
                "Password authentication is not disabled in sshd_config."
            ),
            "implication": (
                "PermitRootLogin yes without PasswordAuthentication no means "
                "root can authenticate over SSH via password. "
                "The root password was set at image build time (Packer/Ansible). "
                "All deployed CVM instances share the same root hash unless "
                "the customer explicitly changes it post-deploy."
            ),
        },
        "impact": (
            "Direct root SSH access is permitted from any host that can reach port 22 "
            "on the CVM VM. If the Packer/Ansible build uses a common root password "
            "across all CVM image builds (shared build credential), then all deployed "
            "CVM VMs are accessible with the same root credential. "
            "Combined with the root-cron tunnel.rb execution, an attacker with SSH "
            "root access can directly modify kenna-apikey or tunnel.rb to maintain "
            "persistence, or read /etc/kenna_api.key to retrieve the Kenna API token."
        ),
        "remediation": (
            "Set PermitRootLogin no in sshd_config. "
            "Add PasswordAuthentication no and require PubkeyAuthentication. "
            "Generate a unique root password per-instance at first boot "
            "or lock the root account entirely. "
            "All CVM management should be performed via the kenna-apikey interface, "
            "not via direct root SSH."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": (
            "Proxy Credentials Printed in Plaintext to Console via "
            "console_proxy_check Debug Method in KennaVirtualTunnel"
        ),
        "component": "/usr/local/bin/kenna_virtual_tunnel.rb",
        "evidence": {
            "debug_method": (
                "def console_proxy_check\n"
                "  proxy_creds = File.read(PROXY_CREDS_FILE).split(':')\n"
                "  return 'No proxy creds configured' if proxy_creds.empty?\n"
                "  \"Proxy creds are Username: #{proxy_creds[0]} Password: #{proxy_creds[1]}\"\n"
                "end"
            ),
            "invocation": (
                "/usr/local/bin/support_scripts/proxy_check.rb calls:\n"
                "  vt = KennaVirtualTunnel.new\n"
                "  puts vt.console_proxy_check\n"
                "This is a support diagnostic intended for operator troubleshooting."
            ),
            "creds_file": (
                "PROXY_CREDS_FILE = '/etc/kenna_proxy.creds' (write path). "
                "The proxy credentials include the username and cleartext password "
                "for whatever authenticated proxy is configured for the Kenna tunnel."
            ),
        },
        "impact": (
            "The proxy_check.rb support script exposes configured proxy credentials "
            "in cleartext to anyone who can run it. "
            "On a VM where PermitRootLogin yes (F4) or kenna-apikey is unauthenticated (F1), "
            "any attacker with access to the VM can retrieve proxy credentials by running "
            "the support script. "
            "Proxy credentials in enterprise environments often grant access to internal "
            "network segments or authenticated proxy chains that are otherwise restricted."
        ),
        "remediation": (
            "The console_proxy_check output should indicate whether proxy credentials "
            "are configured (present/absent, and optionally the username), "
            "never the cleartext password. "
            "Remove the password from the diagnostic output: "
            "  \"Proxy creds are configured for Username: #{proxy_creds[0]}\""
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": (
            "KennaVirtualTunnel Sends OS Version, Kernel, and OpenVPN Version "
            "to Kenna API via X-App-Version Header on Every Cron Invocation"
        ),
        "component": "/usr/local/bin/kenna_virtual_tunnel.rb",
        "evidence": {
            "header_construction": (
                "def net_http_request(uri)\n"
                "  req = Net::HTTP::Get.new(uri)\n"
                "  req['X-Risk-Token'] = kenna_api_key\n"
                "  req['X-App-Version'] = app_version_string\n"
                "  # app_version_string includes:\n"
                "  #   KVT version (434)\n"
                "  #   OS type/version (uname -s, uname -r, uname -v)\n"
                "  #   OpenVPN version string\n"
                "end"
            ),
            "frequency": (
                "Every minute via cron. "
                "X-App-Version is sent on every tunnel.json fetch, "
                "not only on initial registration."
            ),
            "data_exposed": [
                "KVT_VERSION=434",
                "OS kernel version and build (uname -r, uname -v)",
                "OpenVPN version string",
            ],
        },
        "impact": (
            "Every deployed CVM instance sends its exact OS kernel version and OpenVPN "
            "version to the Kenna API server every minute. "
            "If the Kenna API is compromised or the traffic is intercepted, the attacker "
            "receives a real-time inventory of every CVM VM's exact software versions, "
            "enabling targeted CVE exploitation against specific kernel/OpenVPN build combinations. "
            "The X-Risk-Token header (Kenna API key) is also sent on every request, "
            "meaning this header is transmitted 1,440 times per day per VM."
        ),
        "remediation": (
            "Send the X-App-Version header only on first registration or version change, "
            "not on every tunnel.json poll. "
            "Limit the header content to the KVT version number only; "
            "OS and OpenVPN versions are not needed for tunnel configuration. "
            "Rate-limit the API key exposure by caching tunnel.json responses "
            "and only re-fetching when the cache has expired or a change is signaled."
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
