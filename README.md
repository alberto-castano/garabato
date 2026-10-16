# Garabato

An Electron, TypeScript, React, and shadcn/ui application for local PDF signing. No Java runtime or AutoFirma installation is required.

See the [development roadmap](docs/ROADMAP.md) for prioritized issues, acceptance criteria, and dependencies.

## First milestone

- Choose an unsigned PDF and an RSA `.p12` or `.pfx` certificate.
- Unlock the certificate and review its identity before signing.
- Add a detached SHA-256/RSA CMS signature and save a new PDF.
- Keep the original file unchanged. Existing destinations are never overwritten.
- Clear certificate data after a successful save, session reset, or window close.

PDFs are limited to 25 MiB; certificate files to 2 MiB. The certificate needs one matching RSA private key in a protected PKCS#12 key bag.

## Development

Use Bun 1.4.0 and Node 24.14.1 or a compatible current Node release.

```sh
bun install --frozen-lockfile
bun run dev
```

If Electron reports a missing binary after installation, run `node node_modules/electron/install.js`.

```sh
bun run typecheck
bun run lint
bun run test
```

Tests require OpenSSL with the `cms` command. They generate disposable certificates and verify signed bytes independently.
OpenSSL is a test dependency; the application does not invoke it.

`bun run build` compiles the application. `bun run start` opens that compiled output.
Installer packaging, app signing, and notarization are not configured yet.

## Current limits

This is a local signing milestone, not a complete AutoFirma replacement.
It rejects encrypted PDFs, XFA forms, PDFs with existing signatures, invalid certificate dates, and unsupported key containers.
It does not provide a visible signature stamp, certificate trust validation, revocation checks, timestamps, or full PAdES validation.
Keychain, Windows certificate stores, DNIe, hardware tokens, XAdES, CAdES, batch signing, and `afirma://` website integration are not implemented.

The password is retained in main-process memory until the certificate is cleared. It is never written to application storage.
JavaScript cannot guarantee that every copied string is erased from memory. Do not treat memory cleanup as secure erasure.
PDF parsing and signing currently run in the main process; large or complex inputs can pause the window.

See [dependency decisions and audit results](docs/dependencies.md).
The test suite checks cryptographic output, file preservation, session cleanup, IPC authorization, and UI state transitions.
A native application launch, visual review, production build, and installer tests remain to be performed.

## Architecture

The React renderer uses a narrow preload API. Electron owns native dialogs, file access, and signing.
The renderer receives document and certificate metadata, never private-key bytes or unrestricted filesystem APIs.
Context isolation and sandboxing are enabled. Navigation, new windows, and permission requests are blocked.

The [AutoFirma analysis](research/autofirma/ANALYSIS.md) remains a historical reference.
Its Java-bridge proposal was superseded by the Java-free direction. Decompiled AutoFirma code is not used by this application.
