# PDF Signature Toolkit

A small, reproducible toolkit for LaTeX source-integrity records and `adbe.pkcs7.detached` PDF signatures. The Python runtime uses only the standard library. Cryptographic and PDF operations are performed by established command-line tools.

## Capabilities

- Seal LaTeX source with a named signatory, UTC timestamp, payload SHA-256, and complete-source SHA-256.
- Verify the source payload, final source bytes, signature block, and detached JSON record.
- Sign an unsigned PDF with a temporary self-signed certificate or an existing CA-backed PKCS #12 bundle.
- Export the public certificate and detached CMS/PKCS #7 signature.
- Verify SHA-256, total-document coverage, signature type, attachment count, public-certificate identity, and record hashes.
- Write updated files atomically and remove temporary private keys and NSS databases after every run.

## Requirements

- Python 3.10 or later
- OpenSSL (`openssl`)
- Poppler (`pdfsig` and `pdfdetach`)
- NSS tools (`certutil` and `pk12util`)

On Debian or Ubuntu, the external tools are provided by the `openssl`, `poppler-utils`, and `libnss3-tools` packages.

Install the Python commands:

```bash
python3 -m pip install .
pdf-sign --version
pdf-verify --version
```

Without installation, run from the repository root:

```bash
PYTHONPATH=. python3 -m pdf_signature_toolkit.sign --help
PYTHONPATH=. python3 -m pdf_signature_toolkit.verify --help
```

## 1. Seal LaTeX source

```bash
pdf-sign source \
  --source paper.tex \
  --signer "Nicholas Michael Kloster" \
  --signer-id "1505393089" \
  --evidence model=evidence/model-report.json
```

The default record is `paper.signature.json`. Use `--record` to choose another path or `--output-source` to write a sealed copy instead of updating the input source. An existing `--output-source` file is not overwritten unless `--force` is supplied.

The signed payload is the exact UTF-8 byte sequence before `\section{Source signature}`. The final source hash covers the complete file, including the signature block. Keeping two hashes avoids a circular self-reference. Re-sealing replaces an existing Source signature section, preserves evidence hashes unless new evidence is supplied, and removes stale PDF metadata from the record.

Verify it:

```bash
pdf-verify source --source paper.tex --record paper.signature.json
```

This source record is an integrity mechanism. It is not, by itself, proof of identity or a trusted timestamp.

## 2. Sign with a temporary self-signed certificate

```bash
pdf-sign pdf \
  --pdf paper.pdf \
  --source paper.tex \
  --record paper.signature.json \
  --signer "Nicholas Michael Kloster" \
  --signer-id "1505393089" \
  --organization "Independent Research" \
  --country "US" \
  --expect-attachments 55
```

Default outputs for `paper.pdf` are:

```text
paper-signed.pdf
paper-signing-cert.pem
paper.p7s
paper.signature.json
```

The source and its existing record are verified before signing. The PDF record is updated only after the new signature passes validation. Existing PDF, certificate, and detached-signature outputs are not overwritten unless `--force` is supplied.

Verify the result:

```bash
pdf-verify pdf \
  --pdf paper-signed.pdf \
  --source paper.tex \
  --record paper.signature.json \
  --certificate paper-signing-cert.pem \
  --detached paper.p7s \
  --no-cert-validation \
  --expect-attachments 55
```

`--no-cert-validation` is appropriate only when you have independently decided to trust a known self-signed certificate. It skips certificate-chain validation, not cryptographic signature verification. The toolkit still requires a valid SHA-256 `adbe.pkcs7.detached` signature covering the total document.

## 3. Sign with a CA-backed certificate

Provide a PKCS #12 bundle containing the signing certificate and private key. The bundle's friendly name is the required nickname:

```bash
pdf-sign pdf \
  --pdf paper.pdf \
  --pkcs12 signer.p12 \
  --nickname "friendlyName" \
  --field-name "Authorized Signer" \
  --record paper.signature.json
```

The command prompts for the bundle password without echoing it. Alternatively, set `PDF_SIGNATURE_PKCS12_PASSWORD` in the environment for automation. The password is written only to a protected temporary file and is never placed in the signature record.

Verify with normal certificate validation:

```bash
pdf-verify pdf \
  --pdf paper-signed.pdf \
  --record paper.signature.json \
  --certificate paper-signing-cert.pem \
  --detached paper.p7s
```

The issuing CA must be trusted by the verifying NSS configuration. Use `--nssdir` to select a controlled NSS database. Online OCSP checking is off by default; enable it explicitly with `--ocsp` when network validation is required.

## Security and reproducibility

- Self-signed certificates provide document integrity, not independent identity validation.
- CA-backed certificates can provide chain-of-trust validation, but only when the verifier trusts the issuing CA and checks the complete chain.
- Signing-time information comes from the local system. No trusted timestamp authority, military validation, or regulatory compliance is implied.
- Temporary private keys and NSS databases are created in a private temporary directory and deleted on success or failure. The temporary NSS database has an empty password; its private directory and short lifetime protect it. Existing PKCS #12 files are read but never modified.
- Output records contain filenames and hashes, not private keys or local directory paths.
- Repeating a signature with a new key or at a new time changes the signed PDF bytes. Source payload hashes are reproducible only when the source payload is unchanged.
- A record alone does not make an attached artifact trustworthy. Verify the PDF signature, source hashes, evidence hashes, and attachment inventory together.

Use `pdf-sign pdf --help` and `pdf-verify pdf --help` for all options.
