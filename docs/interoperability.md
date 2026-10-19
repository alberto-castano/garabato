# Interoperability results

This document records how independent PDF readers validate Garabato signatures.
It tracks [#3](https://github.com/alberto-castano/garabato/issues/3).

## Validity and trust

Readers report two separate results for each signature:

- **Mathematical validity.** The CMS signature matches the signed bytes, and the signed range covers the whole file. Garabato controls this result.
- **Certificate trust.** The reader builds a path from the signer certificate to a trusted root, with valid dates. The reader's trust store controls this result.

Garabato checks only the signer certificate's dates. It does not check the chain, revocation, or trust ([#7](https://github.com/alberto-castano/garabato/issues/7)).
A signature can be mathematically valid and still untrusted. For example, a signer with an expired CA certificate gives this result.

## Fixtures

`tests/support/fnmt.ts` generates a root, an intermediate CA, and a signer certificate for each test run.
The names copy the FNMT-RCM "Persona Física" structure:

| Certificate | Subject |
| --- | --- |
| Root | `C=ES, O=FNMT-RCM PRUEBAS, OU=AC RAIZ FNMT-RCM PRUEBAS` |
| Intermediate | `C=ES, O=FNMT-RCM PRUEBAS, OU=Ceres, CN=AC FNMT Usuarios PRUEBAS` |
| Signer | `C=ES, serialNumber=IDCES-99999999R, GN=MARÍA JOSÉ, SN=MUÑOZ GARCÍA-PELÁEZ, CN=MUÑOZ GARCÍA-PELÁEZ MARÍA JOSÉ - 99999999R` |

Every CA name contains "PRUEBAS". 99999999R is the DNI number reserved for tests.
Fixtures are written to a temporary folder and deleted after the tests. The repository contains no certificates, keys, passwords, or personal documents.

## Automated validation

`tests/interop.test.ts` runs in CI on macOS 15. Each signed PDF is checked by both validators:

| Validator | Version | Trust configuration |
| --- | --- | --- |
| Poppler `pdfsig` | 26.02.0 (Homebrew) | Temporary NSS database: empty, or with only the disposable root |
| pyHanko CLI | 0.5.0, library 0.37.0 (pinned, through `uvx`) | `--trust` with only the disposable root; no revocation checks |

Results recorded on 2026-10-16, macOS 26.4, OpenSSL 3.6.4:

| Input | Garabato | pdfsig | pyHanko |
| --- | --- | --- | --- |
| Unicode FNMT-like identity, empty trust store | Signs | Signature is Valid; Certificate issuer isn't Trusted | — |
| Same, disposable root trusted | Signs | Signature is Valid; Certificate is Trusted | VALID |
| AcroForm text field | Signs; keeps field value | Signature is Valid | VALID |
| One byte changed in the signed range | — | Digest Mismatch | INVALID |
| Page content appended after signing | — | Signature is Valid; no "Total document signed" | INVALID |
| Valid signer, expired intermediate CA | Signs | Signature is Valid | INVALID (no valid path) |
| Visible box on a page rotated 90° or 270° (2026-10-19) | Signs; `pdftoppm` shows the box upright in the chosen place | Signature is Valid | VALID |
| Missing cross-reference table | Repairs and signs | Signature is Valid | VALID |
| Wrong `startxref` offset | Repairs and signs | Signature is Valid | VALID |
| Bytes before the header or after `%%EOF` | Repairs and signs | Signature is Valid | VALID |
| Truncated file | Rejects: cannot read this PDF | — | — |
| Header without objects | Rejects: cannot read this PDF | — | — |
| Wrong certificate password | Rejects: check the password | — | — |
| Expired or not-yet-valid signer | Rejects with the date error | — | — |

Garabato writes a complete new file, not an incremental update. Repaired inputs therefore produce well-formed output. Their original bytes are not preserved.

`tests/signing.test.ts` also covers encrypted PDFs, XFA forms, existing signatures, unsupported key containers, and size limits.

## Supported inputs

| Input | Status |
| --- | --- |
| Unencrypted PDF with at least one page, up to 25 MiB | Supported |
| AcroForm fields | Supported; values are kept |
| Damaged cross-reference data that pdf-lib can rebuild | Supported; output is rewritten |
| Encrypted PDF, XFA form, PDF with an existing signature | Rejected |
| Truncated PDF or PDF without a page tree | Rejected |
| Password-protected RSA PKCS#12 with one key, up to 2 MiB | Supported |
| Certificate chain in the PKCS#12 | Embedded in the signature; not validated |
| Signer outside its validity dates | Rejected |
| Visible box on any page, including rotated and cropped pages | Supported; at least 72 × 24 points |
| Signer name characters outside Windows Latin-1 in the visible box | Shown as `?`; the certificate is unchanged |
| EC keys, unencrypted keys, several keys | Rejected |

## Manual checks

Both checks were done on 2026-10-16, macOS 26.4, with the disposable fixtures.

| Check | Status |
| --- | --- |
| Adobe Acrobat 26.002.22008 on macOS 26.4: validity, trust, tampering, and changes after signing | Done. See the results below. |
| Native Electron 44.8.0 flow: choose, unlock, sign, save, cancel, overwrite refusal, and reset | Done, development build. See the results below. |

Adobe Acrobat 26.002.22008, macOS 26.4, 2026-10-16. The disposable root was not trusted:

| Input | Acrobat status |
| --- | --- |
| Signed PDF | "La validez de la firma es DESCONOCIDA". No changes since signing. Path to the issuer built. Signer unknown because no certificate in the chain is trusted. |
| Signed AcroForm | Same result as the signed PDF. |
| One byte changed in the signed range | "La firma NO ES VÁLIDA". The document was changed or damaged after signing. |
| Signed PDF, disposable root trusted | "La firma es VÁLIDA, firmada por MUÑOZ GARCÍA-PELÁEZ MARÍA JOSÉ - 99999999R". Trust comes from the manually imported identity. Revocation checks were not possible. |
| Page content appended after signing | "La firma NO ES VÁLIDA". The document was changed or damaged after the signature was applied. |

Acrobat shows the Unicode signer name correctly: `MUÑOZ GARCÍA-PELÁEZ MARÍA JOSÉ - 99999999R`.

An incremental update must use the same cross-reference format as the signed revision. Acrobat rejected the signed byte range when an xref stream followed an xref table. That fixture was a test error, not a Garabato output. With a matching xref table, Acrobat reports the change after signing.

Native Electron 44.8.0 flow, development build (`bun run dev`):

| Step | Result |
| --- | --- |
| Choose PDF, choose certificate, unlock with a Unicode password | Pass. Signer and issuer shown with Unicode names. |
| Sign and save a copy | Pass. "Signed copy saved"; the original PDF is unchanged. |
| Cancel the save dialog and the PDF chooser | Pass. No error; the current selection stays. |
| Save over an existing file, after confirming "Replace" in macOS | Pass. Garabato refuses the save and keeps the existing file. |
| Wrong password, expired signer, already signed PDF | Pass. Each shows its error message. |
| Sign an AcroForm | Pass. Acrobat shows the field value and a valid signature. |
| Clear session | Pass. Returns to the empty state and clears the password. |
| Open the app output in Acrobat | Pass. No changes since signing; signer unknown without the trusted root. |

To run them, generate fixtures with `fnmtIdentity()` into a folder outside the repository.
Acrobat imports `.cer` files, not `.pem` files. Convert the root with `openssl x509 -outform DER`. In Acrobat, import the disposable root only temporarily, and remove it afterwards.
Record each reader's version and the exact status text in this document.
