# Dependency decisions

Checked against npm registry metadata and the projects' GitHub repositories on 2026-10-16.
Versions are pinned in package.json and bun.lock.

## Signing

- `@signpdf/signer-p12` and `@signpdf/placeholder-pdf-lib`: 3.3.0, released 2025-12-29. The [project](https://github.com/vbuch/node-signpdf) had activity on 2026-10-13 and approximately 942 stars. MIT licensed.
- `pdf-lib`: 1.17.1, released 2021-11-06. The [repository](https://github.com/Hopding/pdf-lib) was last pushed in July 2024 and had approximately 8,661 stars. Its age is a maintenance risk. Used for unsigned PDF preparation only, with independent signature tests.
- `node-forge`: 1.4.0, released 2026-03-24. The [repository](https://github.com/digitalbazaar/forge) had activity in September 2026 and approximately 5,341 stars. Used for PKCS#12 parsing and CMS signing through the signpdf signer.

`bun audit` reports one high-severity advisory: [GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv).
It affects node-forge RSA PKCS#1 v1.5 signature verification through 1.4.0. No patched version was listed at inspection.
Garabato does not call forge's RSA verification or certificate-chain verification functions. Tests use OpenSSL for independent verification.
This limits exposure to the reported path; it does not make the dependency audit clean.
Do not introduce verification through forge without resolving this advisory. Reassess or replace the dependency before distribution.

The tracked Bun patch for `@signpdf/signer-p12@3.3.0` preserves the original ASN.1 issuer Name in CMS SignerInfo.
Forge's attribute serializer otherwise double-encodes UTF-8 and flattens multi-valued RDN groups.
The patch copies the issuer from the original certificate structure into the generated CMS signer identifier.
It leaves the original certificate DER, signed attributes, and cryptographic signature unchanged.
Without the patch, OpenSSL cannot locate the signer certificate for these issuers. Regression tests cover both cases.
The application also resolves indirect AcroForm entries, selects a unique signature field name, and omits unsafe PDF Name metadata.
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
