import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone


class ToolkitError(RuntimeError):
    pass


def timestamp_utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_bytes(path, data, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def atomic_write_text(path, text, mode=0o644):
    atomic_write_bytes(path, text.encode("utf-8"), mode)


def atomic_write_json(path, record):
    atomic_write_text(path, json.dumps(record, indent=2, ensure_ascii=False) + "\n")


def atomic_copy(source, destination):
    source = Path(source)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            with source.open("rb") as input_stream:
                shutil.copyfileobj(input_stream, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def load_record(path):
    path = Path(path)
    if not path.is_file():
        raise ToolkitError(f"Signature record not found: {path}")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitError(f"Invalid signature record: {path}: {exc}") from exc
    if not isinstance(record, dict):
        raise ToolkitError("Signature record must contain a JSON object")
    return record


def require_tools(*names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise ToolkitError(f"Missing required command-line tools: {', '.join(missing)}")


def run_tool(command, cwd=None):
    command = [str(part) for part in command]
    try:
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise ToolkitError(f"Could not execute {command[0]}: {exc}") from exc
    output = result.stdout + result.stderr
    if result.returncode:
        raise ToolkitError(f"{command[0]} failed with exit code {result.returncode}:\n{output.strip()}")
    return output


def ensure_output(path, force=False, protected=()):
    path = Path(path)
    for other in protected:
        if other is not None and path.resolve() == Path(other).resolve():
            raise ToolkitError(f"Output must not overwrite an input file: {path}")
    if path.exists() and (path.is_dir() or not force):
        raise ToolkitError(f"Output already exists; use --force to replace it: {path}")


def validate_identity(value, subject=False):
    if not value or any(ord(character) < 32 for character in value):
        raise ToolkitError("Identity fields must be nonempty and cannot contain control characters")
    if subject and "/" in value:
        raise ToolkitError("OpenSSL subject fields cannot contain '/'")
    return value


def format_signer(name, signer_id=None):
    name = validate_identity(name, subject=True)
    if signer_id is not None:
        signer_id = validate_identity(signer_id, subject=True)
        return f"{name} [{signer_id}]"
    return name


def attachment_count(pdf_path):
    output = run_tool(["pdfdetach", "-list", pdf_path])
    match = re.search(r"(?m)^(\d+) embedded files", output)
    if not match:
        raise ToolkitError("Could not determine the PDF attachment count")
    return int(match.group(1))


def inspect_pdf(pdf_path, no_cert_validation=False, ocsp=False, nssdir=None):
    command = ["pdfsig"]
    if no_cert_validation:
        command.append("-nocert")
    if not ocsp:
        command.append("-no-ocsp")
    if nssdir is not None:
        command.extend(["-nssdir", nssdir])
    command.append(pdf_path)
    output = run_tool(command)
    signatures = re.findall(r"(?m)^Signature #\d+:", output)
    if len(signatures) != 1:
        raise ToolkitError(f"Expected exactly one PDF signature, found {len(signatures)}")

    def field(name):
        match = re.search(rf"(?m)^\s*- {re.escape(name)}:\s*(.*?)\s*$", output)
        return match.group(1) if match else None

    if field("Signature Validation") != "Signature is Valid.":
        raise ToolkitError(f"PDF signature is not valid:\n{output}")
    if field("Signature Type") != "adbe.pkcs7.detached":
        raise ToolkitError(f"Expected adbe.pkcs7.detached, found {field('Signature Type')!r}")
    if field("Signing Hash Algorithm") != "SHA-256":
        raise ToolkitError(f"Expected SHA-256, found {field('Signing Hash Algorithm')!r}")
    if "Total document signed" not in output:
        raise ToolkitError("The PDF signature does not cover the total document")
    return {
        "field_name": field("Signature Field Name"),
        "common_name": field("Signer Certificate Common Name"),
        "distinguished_name": field("Signer full Distinguished Name"),
        "signing_time_reported": field("Signing Time"),
        "hash_algorithm": field("Signing Hash Algorithm"),
        "signature_type": field("Signature Type"),
        "signed_ranges": field("Signed Ranges"),
        "total_document_signed": True,
        "signature_validation": field("Signature Validation"),
        "certificate_validation": field("Certificate Validation") or "not_checked",
    }


def certificate_details(certificate_path):
    subject = run_tool([
        "openssl", "x509", "-in", certificate_path, "-noout", "-subject", "-nameopt", "multiline",
    ])
    match = re.search(r"(?m)^\s*commonName\s*=\s*(.*?)\s*$", subject)
    if not match:
        raise ToolkitError("The signing certificate has no common name")
    fingerprint_output = run_tool([
        "openssl", "x509", "-in", certificate_path, "-noout", "-fingerprint", "-sha256",
    ])
    fingerprint = fingerprint_output.split("=", 1)[-1].strip().replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        raise ToolkitError("Could not determine the certificate SHA-256 fingerprint")
    return {"common_name": match.group(1), "sha256_fingerprint": fingerprint}
