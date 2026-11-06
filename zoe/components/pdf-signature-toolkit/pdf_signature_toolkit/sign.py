import argparse
import json
from pathlib import Path
import re
import sys

from . import __version__
from .common import ToolkitError
from .pdf import sign_pdf
from .source import seal_source


def evidence_values(entries):
    evidence = {}
    for entry in entries or []:
        if "=" not in entry:
            raise ToolkitError(f"Evidence must use NAME=PATH: {entry}")
        name, path = entry.split("=", 1)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ToolkitError(f"Invalid evidence name: {name!r}")
        if not Path(path).is_file():
            raise ToolkitError(f"Evidence file not found: {path}")
        evidence[name] = path
    return evidence


def pdf_record_path(pdf_path):
    name = pdf_path.name
    if name.endswith("-signed.pdf"):
        name = name[:-len("-signed.pdf")] + ".pdf"
    return pdf_path.with_name(Path(name).stem + ".signature.json")


def build_parser():
    parser = argparse.ArgumentParser(prog="pdf-sign", description="Seal LaTeX source or sign a PDF")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("source", help="Write or replace a LaTeX source-integrity block")
    source.add_argument("--source", type=Path, required=True)
    source.add_argument("--record", type=Path)
    source.add_argument("--output-source", type=Path)
    source.add_argument("--force", action="store_true", help="Allow replacing an existing output-source file")
    source.add_argument("--signer", required=True)
    source.add_argument("--signer-id")
    source.add_argument("--evidence", action="append", metavar="NAME=PATH")
    pdf = commands.add_parser("pdf", help="Create an adbe.pkcs7.detached PDF signature")
    pdf.add_argument("--pdf", type=Path, required=True)
    pdf.add_argument("--output", type=Path)
    pdf.add_argument("--certificate", type=Path)
    pdf.add_argument("--detached", type=Path)
    pdf.add_argument("--record", type=Path)
    pdf.add_argument("--source", type=Path, help="Optionally verify sealed LaTeX source before signing")
    pdf.add_argument("--signer", help="Required for a temporary self-signed certificate")
    pdf.add_argument("--signer-id")
    pdf.add_argument("--organization")
    pdf.add_argument("--country")
    pdf.add_argument("--days", type=int, default=365)
    pdf.add_argument("--nickname")
    pdf.add_argument("--field-name")
    pdf.add_argument("--reason", default="Document integrity and evidence preservation")
    pdf.add_argument("--pkcs12", type=Path, help="Existing CA-backed certificate and private-key bundle")
    pdf.add_argument("--password-env", default="PDF_SIGNATURE_PKCS12_PASSWORD")
    pdf.add_argument("--expect-attachments", type=int)
    pdf.add_argument("--force", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "source":
            record = args.record or args.source.with_suffix(".signature.json")
            result = seal_source(
                args.source, record, args.signer, args.signer_id,
                output_source=args.output_source,
                evidence=evidence_values(args.evidence),
                force=args.force,
            )
        else:
            output = args.output or args.pdf.with_name(args.pdf.stem + "-signed.pdf")
            certificate = args.certificate or args.pdf.with_name(args.pdf.stem + "-signing-cert.pem")
            detached = args.detached or args.pdf.with_suffix(".p7s")
            record = args.record or pdf_record_path(args.pdf)
            result = sign_pdf(
                args.pdf, output, certificate, detached, record,
                source_path=args.source,
                signer=args.signer,
                signer_id=args.signer_id,
                organization=args.organization,
                country=args.country,
                days=args.days,
                nickname=args.nickname,
                field_name=args.field_name,
                reason=args.reason,
                pkcs12_path=args.pkcs12,
                password_env=args.password_env,
                force=args.force,
                expected_attachments=args.expect_attachments,
            )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ToolkitError, OSError, UnicodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
