import base64
import subprocess

import pytest

from ablation.core.junos_signature import parse_signature, verify_detached


def _openssl(*arguments: str) -> None:
    subprocess.run(["openssl", *arguments], check=True, capture_output=True)


def _signed_payload(tmp_path, kind: str):
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"Junos signature test payload")
    key = tmp_path / "key.pem"
    certificate = tmp_path / "cert.pem"
    signer = f"PackageProduction{kind.upper()}_Test"
    if kind == "rsa":
        _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={signer}", "-keyout", str(key), "-out", str(certificate), "-days", "1")
    else:
        _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", f"/CN={signer}", "-keyout", str(key), "-out", str(certificate), "-days", "1")
    signature_binary = tmp_path / "signature.bin"
    _openssl("dgst", "-sha1", "-sign", str(key), "-out", str(signature_binary), str(payload))
    marker = "JUNOS EC SIGNATURE" if kind == "ec" else "JUNOS SIGNATURE"
    body = base64.b64encode(signature_binary.read_bytes()).decode()
    signature = tmp_path / "payload.sig"
    signature.write_text(f"/CN={signer}\n-----BEGIN {marker}-----\n{body}\n-----END {marker}-----\n")
    return payload, signature, certificate


@pytest.mark.parametrize("kind", ["rsa", "ec"])
def test_verify_detached_rsa_and_ec(tmp_path, kind):
    payload, signature, certificate = _signed_payload(tmp_path, kind)

    result = verify_detached(payload, signature, certificate)

    assert result.valid
    assert result.chain_valid
    assert result.kind == kind
    assert result.signer.startswith("PackageProduction")


def test_verify_detached_rejects_modified_payload(tmp_path):
    payload, signature, certificate = _signed_payload(tmp_path, "rsa")
    payload.write_bytes(b"modified")

    result = verify_detached(payload, signature, certificate)

    assert not result.valid


def test_parse_signature_requires_valid_container(tmp_path):
    path = tmp_path / "invalid.sig"
    path.write_text("not a signature")
    with pytest.raises(ValueError, match="detached signature"):
        parse_signature(path)
