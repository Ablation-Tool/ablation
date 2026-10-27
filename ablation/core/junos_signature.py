"""Verify Junos detached RSA and EC package signatures with OpenSSL."""
from __future__ import annotations

import base64
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_CERTIFICATE_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_SIGNATURE_RE = re.compile(
    r"-----BEGIN JUNOS (?P<kind>EC )?SIGNATURE-----\n(?P<body>.*?)-----END JUNOS (?:EC )?SIGNATURE-----",
    re.DOTALL,
)


@dataclass(frozen=True)
class JunosSignature:
    subject: str
    kind: str
    data: bytes

    @property
    def common_name(self) -> str:
        match = re.search(r"(?:^|/)CN=([^/]+)", self.subject)
        return match.group(1) if match else ""


@dataclass(frozen=True)
class SignatureVerification:
    payload: str
    signature: str
    signer: str
    kind: str
    digest: str
    valid: bool
    chain_valid: bool | None
    detail: str


def parse_signature(path: str | Path) -> JunosSignature:
    text = Path(path).read_text()
    match = _SIGNATURE_RE.search(text)
    if match is None:
        raise ValueError(f"Not a Junos detached signature: {path}")
    subject = text[:match.start()].strip().splitlines()[0].strip()
    kind = "ec" if match.group("kind") else "rsa"
    try:
        data = base64.b64decode("".join(match.group("body").split()), validate=True)
    except ValueError as exc:
        raise ValueError(f"Invalid Junos signature encoding: {path}") from exc
    if not data:
        raise ValueError(f"Empty Junos signature: {path}")
    return JunosSignature(subject=subject, kind=kind, data=data)


def _run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, capture_output=True, text=True, check=False)


def _write_certificates(bundle: str | Path, directory: Path) -> list[Path]:
    text = Path(bundle).read_text()
    certificates = []
    for index, match in enumerate(_CERTIFICATE_RE.finditer(text)):
        path = directory / f"cert-{index}.pem"
        path.write_text(match.group(0) + "\n")
        certificates.append(path)
    if not certificates:
        raise ValueError(f"No certificates found in {bundle}")
    return certificates


def _subject_cn(certificate: Path) -> str:
    result = _run(["openssl", "x509", "-in", str(certificate), "-noout", "-subject", "-nameopt", "compat"])
    if result.returncode != 0:
        return ""
    match = re.search(r"\bCN\s*=\s*([^,/]+)", result.stdout.strip())
    return match.group(1).strip() if match else ""


def verify_detached(
    payload: str | Path,
    signature_path: str | Path,
    certificate_bundle: str | Path,
    digest: str = "sha1",
) -> SignatureVerification:
    signature = parse_signature(signature_path)
    with tempfile.TemporaryDirectory(prefix="ablation-junos-sig-") as temporary:
        work = Path(temporary)
        certificates = _write_certificates(certificate_bundle, work)
        leaf = next((cert for cert in certificates if _subject_cn(cert) == signature.common_name), None)
        if leaf is None:
            return SignatureVerification(
                payload=str(payload),
                signature=str(signature_path),
                signer=signature.common_name,
                kind=signature.kind,
                digest=digest,
                valid=False,
                chain_valid=None,
                detail="No certificate matching the signature subject",
            )
        signature_file = work / "signature.bin"
        signature_file.write_bytes(signature.data)
        public_key = work / "public.pem"
        with open(public_key, "w") as output:
            subprocess.run(
                ["openssl", "x509", "-in", str(leaf), "-pubkey", "-noout"],
                stdout=output,
                stderr=subprocess.PIPE,
                check=False,
            )
        result = _run([
            "openssl", "dgst", f"-{digest}", "-verify", str(public_key),
            "-signature", str(signature_file), str(payload),
        ])
        root = certificates[-1]
        intermediates = [cert for cert in certificates[1:-1] if cert != leaf]
        chain_command = ["openssl", "verify", "-CAfile", str(root)]
        if intermediates:
            chain_command.extend(["-untrusted", str(intermediates[0])])
            for cert in intermediates[1:]:
                chain_command.extend(["-untrusted", str(cert)])
        chain_command.append(str(leaf))
        chain = _run(chain_command)
        detail = result.stdout.strip() or result.stderr.strip()
        return SignatureVerification(
            payload=str(payload),
            signature=str(signature_path),
            signer=signature.common_name,
            kind=signature.kind,
            digest=digest,
            valid=result.returncode == 0,
            chain_valid=chain.returncode == 0,
            detail=detail,
        )


def verify_package_directory(root: str | Path) -> list[SignatureVerification]:
    base = Path(root)
    results: list[SignatureVerification] = []
    for signature_path in sorted(base.rglob("*.sig")) + sorted(base.rglob("*.esig")):
        payload = signature_path.with_suffix("")
        if not payload.is_file():
            continue
        bundle_name = "ecerts.pem" if signature_path.suffix == ".esig" else "certs.pem"
        bundle = signature_path.parent / bundle_name
        if not bundle.is_file():
            bundle = base / bundle_name
        results.append(verify_detached(payload, signature_path, bundle))
    return results
