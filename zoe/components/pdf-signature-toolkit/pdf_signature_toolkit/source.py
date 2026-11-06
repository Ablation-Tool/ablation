from pathlib import Path
import re

from .common import (
    ToolkitError,
    atomic_write_json,
    atomic_write_text,
    format_signer,
    load_record,
    sha256_bytes,
    timestamp_utc,
)

SOURCE_MARKER = b"\\section{Source signature}"
SOURCE_SECTION = re.compile(rb"(?m)^\\section\{Source signature\}[ \t]*$")
END_DOCUMENT = b"\\end{document}"
PAYLOAD_SCOPE = "UTF-8 LaTeX source preceding \\section{Source signature}"


def latex_escape(value):
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(character, character) for character in value)


def source_payload(source):
    matches = list(SOURCE_SECTION.finditer(source))
    if len(matches) > 1:
        raise ToolkitError("LaTeX source contains more than one Source signature section")
    if matches:
        return source[:matches[0].start()]
    if END_DOCUMENT not in source:
        raise ToolkitError(r"LaTeX source must contain \end{document}")
    return source.rsplit(END_DOCUMENT, 1)[0]


def signature_section(signer, timestamp, payload_hash):
    visible_signer = latex_escape(signer)
    return f"""\\section{{Source signature}}
\\textbf{{Signatory: {visible_signer}}}

\\textbf{{Timestamp (UTC): {timestamp}}}

The UTF-8 LaTeX source payload preceding this section has SHA-256:
\\begin{{verbatim}}
{payload_hash}
\\end{{verbatim}}
This digest binds the named signatory to the exact source payload. It is an integrity record, not a third-party identity certificate.

% SHA256-SIGNATURE-BEGIN
% signer: {signer}
% timestamp_utc: {timestamp}
% payload: {PAYLOAD_SCOPE}
% sha256: {payload_hash}
% SHA256-SIGNATURE-END
\\end{{document}}
"""


def seal_source(source_path, record_path, signer, signer_id=None, output_source=None, evidence=None, force=False):
    source_path = Path(source_path)
    record_path = Path(record_path)
    output_source = Path(output_source) if output_source else source_path
    if output_source.resolve() == record_path.resolve():
        raise ToolkitError("LaTeX source and signature record must be different files")
    if output_source.resolve() != source_path.resolve() and output_source.exists() and not force:
        raise ToolkitError(f"Output source already exists; use --force to replace it: {output_source}")
    if output_source.is_dir() or record_path.is_dir():
        raise ToolkitError("Source and signature-record outputs must be files")
    original = source_path.read_bytes()
    original.decode("utf-8")
    payload = source_payload(original)
    signer = format_signer(signer, signer_id)
    timestamp = timestamp_utc()
    payload_hash = sha256_bytes(payload)
    sealed = payload + signature_section(signer, timestamp, payload_hash).encode("utf-8")
    record = load_record(record_path) if record_path.exists() else {}
    record.pop("pdf", None)
    record.update({
        "signature_version": 1,
        "algorithm": "SHA-256",
        "signer": signer,
        "timestamp_utc": timestamp,
        "payload_scope": PAYLOAD_SCOPE,
        "payload_sha256": payload_hash,
        "signed_source_sha256": sha256_bytes(sealed),
    })
    if evidence:
        evidence_record = record.setdefault("evidence", {})
        for name, path in evidence.items():
            key = name if name.endswith("_sha256") else f"{name}_sha256"
            evidence_record[key] = sha256_bytes(Path(path).read_bytes())
    record.setdefault("integrity_note", "SHA-256 binds the named signer to the exact source payload and evidence values. This is not a third-party identity certificate.")
    mode = source_path.stat().st_mode & 0o777
    atomic_write_text(output_source, sealed.decode("utf-8"), mode=mode)
    atomic_write_json(record_path, record)
    return {
        "operation": "seal-source",
        "source": output_source.name,
        "record": record_path.name,
        "signer": signer,
        "timestamp_utc": timestamp,
        "payload_sha256": payload_hash,
        "signed_source_sha256": record["signed_source_sha256"],
    }


def verify_source(source_path, record_path):
    source_path = Path(source_path)
    source = source_path.read_bytes()
    source.decode("utf-8")
    record = load_record(record_path)
    if record.get("signature_version") != 1 or record.get("algorithm") != "SHA-256":
        raise ToolkitError("Unsupported source-signature record")
    if record.get("payload_scope") != PAYLOAD_SCOPE:
        raise ToolkitError("Unexpected source payload scope")
    if not SOURCE_SECTION.search(source):
        raise ToolkitError("LaTeX source has no Source signature section")
    payload_hash = sha256_bytes(source_payload(source))
    source_hash = sha256_bytes(source)
    if payload_hash != record.get("payload_sha256"):
        raise ToolkitError("LaTeX source payload hash does not match the signature record")
    if source_hash != record.get("signed_source_sha256"):
        raise ToolkitError("Complete LaTeX source hash does not match the signature record")
    signer = record.get("signer")
    timestamp = record.get("timestamp_utc")
    for line in (
        f"% signer: {signer}".encode(),
        f"% timestamp_utc: {timestamp}".encode(),
        f"% sha256: {payload_hash}".encode(),
        f"\\textbf{{Timestamp (UTC): {timestamp}}}".encode(),
        b"% SHA256-SIGNATURE-BEGIN",
        b"% SHA256-SIGNATURE-END",
    ):
        if line not in source:
            raise ToolkitError(f"LaTeX source signature block is missing: {line.decode()!r}")
    return {
        "operation": "verify-source",
        "verified": True,
        "source": source_path.name,
        "record": Path(record_path).name,
        "signer": signer,
        "timestamp_utc": timestamp,
        "payload_sha256": payload_hash,
        "signed_source_sha256": source_hash,
    }
