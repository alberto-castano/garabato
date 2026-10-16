# Dependency decisions

Checked against npm registry metadata and the projects' GitHub repositories on 2026-10-16.
Versions are pinned in package.json and bun.lock.

## Signing

- `@signpdf/placeholder-pdf-lib`: 3.3.0, released 2025-12-29. The [project](https://github.com/vbuch/node-signpdf) had activity on 2026-10-13 and approximately 942 stars. MIT licensed.
- `pdf-lib`: 1.17.1, released 2021-11-06. The [repository](https://github.com/Hopding/pdf-lib) was last pushed in July 2024 and had approximately 8,661 stars. Its age is a maintenance risk. Used for unsigned PDF preparation only, with independent signature tests.
- `pkijs` 3.4.1 (released 2026-09-20) and `asn1js` 3.0.10: the [PeculiarVentures](https://github.com/PeculiarVentures/PKI.js) PKI libraries, BSD-3-Clause, approximately 1,401 stars, last pushed 2026-09-30. Used to build the CMS SignedData. Node `crypto` creates the RSA signature.

Garabato reads PKCS#12 files itself in `src/main/pkcs12.ts`. pkijs parses the ASN.1 structures; Node `crypto` derives keys, checks the MAC, and decrypts.
pkijs alone opens only PBES2 files. Older Windows and OpenSSL exports use the legacy RFC 7292 SHA-1 3DES and RC2 algorithms.
Garabato therefore owns two small, standard pieces, each tested against fixed vectors:

- The RFC 7292 appendix B key derivation, tested against published Bouncy Castle vectors.
- RC2-CBC decryption (RFC 2268) in `src/main/rc2.ts`. Node's OpenSSL 3 default provider has no RC2. Tests use OpenSSL `enc` ciphertexts.

Supported: password MACs with SHA-1 or SHA-2; PBES2 with PBKDF2 and AES-CBC or 3DES; SHA-1 PBE with 3DES, RC2-128, or RC2-40.
Key derivation is limited to 1,000,000 iterations so that a hostile file cannot stall the main process.
Files without a MAC are accepted, as before; the private key must still decrypt with the password.
Tests export OpenSSL files with the default AES, `-legacy`, 3DES-only, and unencrypted-certificate settings, with a non-ASCII password.
An Electron 44.8.0 smoke test (BoringSSL) opened and signed with legacy and AES files.

node-forge was removed. `bun audit` reports no vulnerabilities. Its GHSA-86w9-cpqp-85rv advisory no longer applies.

`src/main/cms.ts` builds a detached SHA-256 RSA SignedData with the contentType, signingTime, and messageDigest signed attributes, in that order.
It embeds the container certificates unchanged and takes the signer identifier from the parsed certificate issuer, which keeps its original DER.
This keeps Unicode and multi-valued RDN issuers intact, so the earlier local `@signpdf/signer-p12` patch is no longer needed. Regression tests verify both cases with OpenSSL.

The application resolves indirect AcroForm entries, selects a unique signature field name, and omits unsafe PDF Name metadata.
These work around confirmed defects in the pinned PDF placeholder helper. The certificate still supplies the signer identity.
The application does not use the generic `@signpdf/signpdf` byte scanner: it can mistake PDF string content for a placeholder.
It locates the complete signature object created by the placeholder helper, checks that the match is unique, and patches only that object's byte range and signature slot.
All replacements keep the serialized PDF length unchanged. Tests preserve literal `/ByteRange` text in an unrelated object and verify the resulting CMS signature.

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
