# Dependency decisions

Checked against npm registry metadata, installed package manifests, and the projects' GitHub repositories on 2026-10-16.
Versions are pinned in package.json and bun.lock.

## Signing

Runtime signing dependencies. Versions are exact pins. Checked on 2026-10-16.

| Package | Version | License | Maintenance | Use |
| --- | --- | --- | --- | --- |
| `pkijs` | 3.4.1 (2026-09-20) | BSD-3-Clause | [PeculiarVentures](https://github.com/PeculiarVentures/PKI.js), last push 2026-09-30, about 1,400 stars | CMS SignedData, PKCS#12 and X.509 ASN.1 structures |
| `asn1js` | 3.0.10 (2026-04-20) | BSD-3-Clause | [PeculiarVentures](https://github.com/PeculiarVentures/ASN1.js) | ASN.1 encoding |
| `@cantoo/pdf-lib` | 2.11.1 (2026-09-15) | MIT | [Cantoo fork of pdf-lib](https://github.com/cantoo-scribe/pdf-lib), last push 2026-09-11, about 360 stars | PDF parsing, preparation, and saving |

Transitive runtime packages: `pvtsutils` 1.3.6 (MIT), `pvutils` 1.2.0 (MIT), `bytestreamjs` 2.0.1 (BSD-3-Clause), and `@noble/hashes` 1.8.0 (MIT) through pkijs;
`fflate` 0.8.3, `culori` 4.0.2, `node-html-better-parser` 1.5.9, and `html-entities` 2.6.0 (all MIT) through the PDF library; `tslib` 2.8.1 (0BSD).
`bun audit` reports no vulnerabilities.

Removed in the #1 stack: `node-forge` (GHSA-86w9-cpqp-85rv, unpatched through 1.4.0), `@signpdf/signer-p12` and its local patch,
`@signpdf/placeholder-pdf-lib`, and `pdf-lib` 1.17.1 (no release since 2021). Garabato has no patched dependencies.

### Code Garabato owns

These pieces replace dependencies that were unmaintained, vulnerable, or patched. Each follows a public standard and has its own tests.

- `src/main/cms.ts`: detached SHA-256 RSA CMS SignedData (RFC 5652) with the contentType, signingTime, and messageDigest signed attributes, in that order.
  It embeds the container certificates unchanged. The signer identifier copies the certificate issuer DER, which keeps Unicode and multi-valued RDNs intact.
- `src/main/pkcs12.ts`: PKCS#12 reader (RFC 7292). pkijs parses the structures; Node `crypto` derives keys, checks the MAC, and decrypts.
  pkijs alone opens only PBES2 files. Older Windows and OpenSSL exports use the legacy SHA-1 3DES and RC2 algorithms.
  The appendix B key derivation is tested against published Bouncy Castle vectors.
- `src/main/rc2.ts`: RC2-CBC decryption (RFC 2268). Node's OpenSSL 3 default provider has no RC2. Tests use OpenSSL `enc` ciphertexts.
- The signature placeholder in `src/main/signing.ts`: a `/Sig` dictionary with `adbe.pkcs7.detached`, an invisible widget, and AcroForm `SigFlags` 3.
  The dictionary is written as fixed bytes, so the byte range and signature slot are at known offsets.

PKCS#12 support: password MACs with SHA-1 or SHA-2; PBES2 with PBKDF2 and AES-CBC or 3DES; SHA-1 PBE with 3DES, RC2-128, or RC2-40.
Key derivation is limited to 1,000,000 iterations so that a hostile file cannot stall the main process.
Files without a MAC are accepted; the private key must still decrypt with the password.

### PDF handling

The application rejects existing signatures, encrypted PDFs, and XFA forms before it changes the document.
It selects a unique signature field name and adds the widget to existing field and annotation arrays, including indirect ones.
The signature dictionary has no text metadata; the certificate supplies the signer identity.
The application does not scan for placeholders: it locates the complete signature object it wrote, checks that the match is unique,
and patches only that object's byte range and signature slot. All replacements keep the serialized PDF length unchanged.

### Regression coverage

`tests/signing.test.ts` and `tests/pkcs12.test.ts` cover these risks. Keep the tests when you change signing code or dependencies:

- Unicode, parentheses, and backslashes in certificate subjects.
- Multi-valued Unicode issuer RDNs in the CMS signer identifier.
- Form fields and flags stored as indirect objects, and unique signature field names.
- Byte-range selection when another object contains literal `/ByteRange` text.
- OpenSSL PKCS#12 exports: default AES, `-legacy`, 3DES-only, and unencrypted certificates, with a non-ASCII password.
- KDF and RC2 known-answer vectors, and the iteration limit.

On 2026-10-16, Poppler `pdfsig` also reported valid, whole-document signatures for AES and legacy containers. It is not part of the test suite.

## Desktop and interface

- Electron 44.8.0 and electron-vite 6.0.0 were current stable npm releases at inspection.
- React 19.3.1, Vite 8.3.4, and TypeScript 7.0.2 were current npm releases.
- shadcn CLI 4.21.5 generated the Base UI Nova components from the official `@shadcn` registry.
- Base UI 1.9.0 supplies the accessible primitives. Tailwind CSS 4.3.3 supplies styling.
- The generated components use shadcn's `cn` 0.4.0 helper. Their source is kept in `src/renderer/src/components/ui`.

Sources: [Electron](https://github.com/electron/electron), [electron-vite](https://github.com/alex8088/electron-vite),
[shadcn/ui](https://ui.shadcn.com/docs), and npm metadata captured during installation.

## Scope of proof

Tests generate a one-page PDF and a disposable RSA certificate. OpenSSL verifies the detached CMS signature and rejects tampered content.
This proves the tested signed-byte flow. It does not establish interoperability with every PDF reader, government website, or signature profile.
The application has no Java dependency and does not use the recovered AutoFirma sources.
