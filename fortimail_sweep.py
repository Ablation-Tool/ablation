"""
FortiMail binary semantic sweep -- FML_VM-64-v800.F-build0183
Targets: smtpd, mailfilterd, httpd, smtpproxy, rescand, imap, pop3, webauthenticator
"""

import sys, os, json, numpy as np
sys.path.insert(0, os.path.dirname(__file__))
import fortinet_sweep
from fortinet_sweep import sweep, VULN_PROFILES

FML_ROOT = os.path.expanduser("~/ablation/fortimail-work/extract/rootfs")

TARGETS = [
    ("smtpd",             "FortiMail SMTP daemon -- inbound mail parsing, EHLO/DATA handling"),
    ("mailfilterd",       "FortiMail mail filter daemon -- MIME parsing, AV/AS pipeline"),
    ("httpd",             "FortiMail custom httpd -- admin console, webmail, API"),
    ("smtpproxy",         "FortiMail SMTP proxy -- header rewriting, relay control"),
    ("rescand",           "FortiMail rescan daemon -- AV re-scan of quarantined mail"),
    ("imap",              "FortiMail IMAP daemon -- mailbox access, FETCH/SEARCH"),
    ("pop3",              "FortiMail POP3 daemon"),
    ("webauthenticator",  "FortiMail web authentication handler"),
]

# FortiMail-specific vulnerability profiles added to the base set
FML_VULN_PROFILES = VULN_PROFILES + [
    ("mime_parser_overflow",
     "MIME_PARSER | role=attachment_decode | calls: memcpy memmove realloc base64_decode | "
     "vuln: MIME boundary or content-length field read from email and used as copy length "
     "without upper bound; heap overflow in attachment decoder"),

    ("smtp_cmd_injection",
     "SMTP_HANDLER | role=command_parse | calls: strcmp strncmp sscanf | "
     "vuln: SMTP command argument (MAIL FROM / RCPT TO / EHLO hostname) passed to shell "
     "or system() without sanitization; OS command injection"),

    ("header_parser_oob",
     "MAIL_HEADER_PARSER | role=header_decode | calls: strcpy sprintf strncat | "
     "vuln: email header value (Subject, From, To, X-custom) copied into fixed-size "
     "stack buffer without length check; stack overflow in header parser"),

    ("imap_literal_overflow",
     "IMAP_HANDLER | role=literal_parse | calls: malloc memcpy read recv | "
     "vuln: IMAP literal length from client ('{NNN}') trusted without upper bound; "
     "allocation and copy of attacker-controlled size before authentication"),

    ("webmail_cmd_exec",
     "WEBMAIL_HANDLER | role=mail_action | calls: popen system execve fork | "
     "vuln: webmail action parameter (message-id, folder name, attachment name) "
     "passed to shell command without sanitization; authenticated RCE"),
]


def run_all(output_file: str = None):
    # Patch the module-level profile list to include FortiMail-specific profiles
    orig_profiles = fortinet_sweep.VULN_PROFILES
    fortinet_sweep.VULN_PROFILES = FML_VULN_PROFILES

    all_results = {}
    for binary_name, label in TARGETS:
        path = os.path.join(FML_ROOT, "bin", binary_name)
        if not os.path.exists(path):
            print(f"[SKIP] {binary_name} not found at {path}")
            continue
        results, metas, descs, corpus_vecs, model = sweep(path, label)
        all_results[binary_name] = {
            "label": label,
            "n_functions": len(metas),
            "hits": results,
        }

    # Restore original profiles
    fortinet_sweep.VULN_PROFILES = orig_profiles

    if output_file:
        with open(output_file, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults written to {output_file}")

    return all_results


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/fml_sweep_results.json"
    run_all(out)
