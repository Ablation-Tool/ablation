import getpass
import os
from pathlib import Path
import secrets
import tempfile

from .common import (
    ToolkitError,
    atomic_copy,
    atomic_write_json,
    attachment_count,
    certificate_details,
    ensure_output,
    format_signer,
    inspect_pdf,
    load_record,
    require_tools,
    run_tool,
    sha256_file,
    timestamp_utc,
    validate_identity,
)
from .source import verify_source


def sign_pdf(
    pdf_path,
    output_path,
    certificate_path,
    detached_path,
    record_path,
    source_path=None,
    signer=None,
    signer_id=None,
    organization=None,
    country=None,
    days=365,
    nickname=None,
    field_name=None,
    reason="Document integrity and evidence preservation",
    pkcs12_path=None,
    password_env="PDF_SIGNATURE_PKCS12_PASSWORD",
    force=False,
    expected_attachments=None,
):
    require_tools("openssl", "pdfsig", "certutil", "pk12util", "pdfdetach")
    pdf_path = Path(pdf_path)
    output_path = Path(output_path)
    certificate_path = Path(certificate_path)
    detached_path = Path(detached_path)
    record_path = Path(record_path)
    source_path = Path(source_path) if source_path else None
    pkcs12_path = Path(pkcs12_path) if pkcs12_path else None
    if not pdf_path.is_file():
        raise ToolkitError(f"Input PDF not found: {pdf_path}")
    if not isinstance(days, int) or days < 1:
        raise ToolkitError("Certificate lifetime must be a positive number of days")
    if expected_attachments is not None and expected_attachments < 0:
        raise ToolkitError("Expected attachment count cannot be negative")
    if source_path is not None:
        verify_source(source_path, record_path)
    if pkcs12_path is not None and not pkcs12_path.is_file():
        raise ToolkitError(f"PKCS #12 bundle not found: {pkcs12_path}")
    if pkcs12_path is None and signer is None:
        raise ToolkitError("Self-signed mode requires --signer")
    if pkcs12_path is not None and not nickname:
        raise ToolkitError("CA-backed mode requires the PKCS #12 certificate nickname")
    if nickname is None:
        nickname = "pdf-signature-toolkit"
    identity = format_signer(signer, signer_id) if signer is not None else None
    if organization is not None:
        validate_identity(organization, subject=True)
    if country is not None:
        validate_identity(country, subject=True)
    if field_name is not None:
        validate_identity(field_name)
    outputs = (output_path, certificate_path, detached_path, record_path)
    if len({path.resolve() for path in outputs}) != len(outputs):
        raise ToolkitError("PDF, certificate, detached-signature, and record outputs must be distinct")
    for output in (output_path, certificate_path, detached_path):
        ensure_output(output, force=force, protected=(pdf_path, source_path, pkcs12_path))
    ensure_output(record_path, force=True, protected=(pdf_path, source_path, pkcs12_path))

    with tempfile.TemporaryDirectory(prefix="pdf-signature-toolkit-") as temporary:
        work = Path(temporary)
        nss = work / "nss"
        nss.mkdir()
        password_file = work / "pkcs12-password"
        empty_password_file = work / "empty-nss-password"
        empty_password_file.write_bytes(b"\n")
        if pkcs12_path is None:
            password_file.write_text(secrets.token_urlsafe(36) + "\n", encoding="utf-8")
            key_path = work / "private-key.pem"
            public_certificate = work / "signing-cert.pem"
            bundle = work / "signing.p12"
            subject = f"/CN={identity}"
            if organization:
                subject += f"/O={organization}"
            if country:
                subject += f"/C={country}"
            run_tool([
                "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256",
                "-days", days, "-nodes", "-subj", subject,
                "-keyout", key_path, "-out", public_certificate,
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature,nonRepudiation",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "authorityKeyIdentifier=keyid,issuer",
            ])
            run_tool([
                "openssl", "pkcs12", "-export", "-out", bundle,
                "-inkey", key_path, "-in", public_certificate,
                "-name", nickname, "-passout", f"file:{password_file}",
            ])
        else:
            bundle = pkcs12_path
            public_certificate = work / "signing-cert.pem"
            password = os.environ.get(password_env)
            if password is None:
                password = getpass.getpass("PKCS #12 password: ")
            password_file.write_text(password + "\n", encoding="utf-8")
            del password
            run_tool([
                "openssl", "pkcs12", "-in", bundle, "-clcerts", "-nokeys",
                "-out", public_certificate, "-passin", f"file:{password_file}",
            ])
        os.chmod(password_file, 0o600)
        os.chmod(empty_password_file, 0o600)
        run_tool(["certutil", "-N", "-d", f"sql:{nss}", "--empty-password"])
        run_tool([
            "pk12util", "-i", bundle, "-d", f"sql:{nss}",
            "-k", empty_password_file, "-w", password_file,
        ])
        certificate = certificate_details(public_certificate)
        signature_field = field_name or identity or certificate["common_name"]
        signed_pdf = work / "signed.pdf"
        run_tool([
            "pdfsig", "-nocert", "-no-ocsp", "-nssdir", nss,
            "-nick", nickname, "-add-signature",
            "-new-signature-field-name", signature_field,
            "-digest", "SHA256", "-reason", reason,
            pdf_path, signed_pdf,
        ])
        inspection = inspect_pdf(signed_pdf, no_cert_validation=True)
        count = attachment_count(signed_pdf)
        if expected_attachments is not None and count != expected_attachments:
            raise ToolkitError(f"Expected {expected_attachments} attachments, found {count}")
        run_tool(["pdfsig", "-dump", signed_pdf], cwd=work)
        detached_signature = work / "signed.pdf.sig0"
        if not detached_signature.is_file():
            raise ToolkitError("pdfsig did not export the detached CMS signature")
        run_tool(["openssl", "cms", "-inform", "DER", "-in", detached_signature, "-cmsout", "-print"])

        atomic_copy(signed_pdf, output_path)
        atomic_copy(public_certificate, certificate_path)
        atomic_copy(detached_signature, detached_path)
        record = load_record(record_path) if record_path.exists() else {}
        record.setdefault("signature_version", 1)
        record.setdefault("algorithm", "SHA-256")
        record.setdefault("signer", identity or certificate["common_name"])
        record["pdf"] = {
            "file": output_path.name,
            "sha256": sha256_file(signed_pdf),
            "signature_type": inspection["signature_type"],
            "total_document_signed": True,
            "signature_validation": "cryptographically_valid",
            "certificate_validation_during_signing": "not_checked",
            "signature_file": detached_path.name,
            "signature_sha256": sha256_file(detached_signature),
            "certificate_file": certificate_path.name,
            "certificate_sha256": sha256_file(public_certificate),
            "certificate_sha256_fingerprint": certificate["sha256_fingerprint"],
            "attachment_count": count,
            "verification_utc": timestamp_utc(),
        }
        atomic_write_json(record_path, record)
    return {
        "operation": "sign-pdf",
        "verified": True,
        "pdf": output_path.name,
        "pdf_sha256": record["pdf"]["sha256"],
        "certificate": certificate_path.name,
        "detached_signature": detached_path.name,
        "record": record_path.name,
        "signer": record["signer"],
        "attachments": count,
        "signature": inspection,
    }


def verify_pdf(
    pdf_path,
    record_path=None,
    source_path=None,
    certificate_path=None,
    detached_path=None,
    expected_attachments=None,
    no_cert_validation=False,
    ocsp=False,
    nssdir=None,
):
    require_tools("openssl", "pdfsig", "pdfdetach")
    pdf_path = Path(pdf_path)
    if not pdf_path.is_file():
        raise ToolkitError(f"Signed PDF not found: {pdf_path}")
    if source_path is not None and record_path is None:
        raise ToolkitError("Source verification requires --record")
    inspection = inspect_pdf(
        pdf_path,
        no_cert_validation=no_cert_validation,
        ocsp=ocsp,
        nssdir=nssdir,
    )
    count = attachment_count(pdf_path)
    if expected_attachments is not None and count != expected_attachments:
        raise ToolkitError(f"Expected {expected_attachments} attachments, found {count}")
    record = load_record(record_path) if record_path else None
    if record is not None and "pdf" in record:
        pdf_record = record["pdf"]
        if sha256_file(pdf_path) != pdf_record.get("sha256"):
            raise ToolkitError("Signed PDF hash does not match the signature record")
        if pdf_record.get("total_document_signed") is not True:
            raise ToolkitError("Signature record does not assert total-document coverage")
    if source_path is not None:
        verify_source(source_path, record_path)
    certificate = None
    if certificate_path is not None:
        certificate = certificate_details(certificate_path)
        if certificate["common_name"] != inspection["common_name"]:
            raise ToolkitError("Certificate common name does not match the PDF signer")
        if record is not None and "pdf" in record:
            expected = record["pdf"].get("certificate_sha256")
            if expected and sha256_file(certificate_path) != expected:
                raise ToolkitError("Public certificate hash does not match the signature record")
            fingerprint = record["pdf"].get("certificate_sha256_fingerprint")
            if fingerprint and certificate["sha256_fingerprint"] != fingerprint:
                raise ToolkitError("Certificate fingerprint does not match the signature record")
    if detached_path is not None:
        run_tool(["openssl", "cms", "-inform", "DER", "-in", detached_path, "-cmsout", "-print"])
        if record is not None and "pdf" in record:
            expected = record["pdf"].get("signature_sha256")
            if expected and sha256_file(detached_path) != expected:
                raise ToolkitError("Detached signature hash does not match the signature record")
    return {
        "operation": "verify-pdf",
        "verified": True,
        "pdf": pdf_path.name,
        "pdf_sha256": sha256_file(pdf_path),
        "attachments": count,
        "source_verified": source_path is not None,
        "certificate": certificate,
        "signature": inspection,
    }
