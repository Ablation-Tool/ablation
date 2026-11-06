import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .common import ToolkitError
from .pdf import verify_pdf
from .sign import pdf_record_path
from .source import verify_source


def build_parser():
    parser = argparse.ArgumentParser(prog="pdf-verify", description="Verify LaTeX source and PDF signatures")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("source", help="Verify a LaTeX source-integrity record")
    source.add_argument("--source", type=Path, required=True)
    source.add_argument("--record", type=Path)
    pdf = commands.add_parser("pdf", help="Verify a PKCS #7 detached PDF signature")
    pdf.add_argument("--pdf", type=Path, required=True)
    pdf.add_argument("--record", type=Path)
    pdf.add_argument("--source", type=Path)
    pdf.add_argument("--certificate", type=Path)
    pdf.add_argument("--detached", type=Path)
    pdf.add_argument("--expect-attachments", type=int)
    pdf.add_argument("--no-cert-validation", action="store_true", help="Skip trust validation for a known self-signed certificate")
    pdf.add_argument("--ocsp", action="store_true", help="Enable online OCSP checks")
    pdf.add_argument("--nssdir", type=Path, help="NSS database containing trusted CA certificates")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "source":
            record = args.record or args.source.with_suffix(".signature.json")
            result = verify_source(args.source, record)
        else:
            record = args.record
            if record is None:
                candidate = pdf_record_path(args.pdf)
                record = candidate if candidate.exists() else None
            elif not record.is_file():
                raise ToolkitError(f"Signature record not found: {record}")
            certificate = args.certificate
            detached = args.detached
            if args.pdf.name.endswith("-signed.pdf"):
                base = args.pdf.with_name(args.pdf.name[:-len("-signed.pdf")])
                if certificate is None:
                    candidate = base.with_name(base.name + "-signing-cert.pem")
                    certificate = candidate if candidate.exists() else None
                if detached is None:
                    candidate = base.with_suffix(".p7s")
                    detached = candidate if candidate.exists() else None
            if certificate is not None and not certificate.is_file():
                raise ToolkitError(f"Certificate not found: {certificate}")
            if detached is not None and not detached.is_file():
                raise ToolkitError(f"Detached signature not found: {detached}")
            result = verify_pdf(
                args.pdf,
                record_path=record,
                source_path=args.source,
                certificate_path=certificate,
                detached_path=detached,
                expected_attachments=args.expect_attachments,
                no_cert_validation=args.no_cert_validation,
                ocsp=args.ocsp,
                nssdir=args.nssdir,
            )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ToolkitError, OSError, UnicodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
