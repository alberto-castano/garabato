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
Supported PKCS#12 encryption: PBES2 with AES or 3DES, and legacy SHA-1 3DES or RC2.

## Development

Use Bun 1.4.0 (`packageManager` in package.json) and Node 24.14.1 (`.node-version`).

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

Tests require OpenSSL 3.4 or later with the `cms` command and the legacy provider. They generate disposable certificates and verify signed bytes independently.
OpenSSL is a test dependency; the application does not invoke it.
On macOS, the system `openssl` is LibreSSL. Install Homebrew `openssl@3` and put its `bin` directory first on `PATH`.

Interoperability tests also need Poppler `pdfsig`, NSS `certutil`, and `uvx` (`brew install poppler uv`).
They run pyHanko through `uvx` at a pinned version, so the first run downloads it.
See [interoperability results](docs/interoperability.md) for the supported-input matrix.

### Continuous integration

[CI](.github/workflows/ci.yml) runs on pull requests, pushes to `main`, and weekly. Its jobs have read-only repository access.

| Job | Runner | Checks |
| --- | --- | --- |
| Typecheck, lint, and test | macOS 15 (arm64), Bun 1.4.0, Node 24.14.1, Homebrew OpenSSL 3.4+ and Poppler, uv | Frozen-lockfile install, OpenSSL version check, `typecheck`, `lint`, `test` |
| Dependency audit | Ubuntu 24.04 | `bun audit`; any advisory fails the job |
| Secret scan | Ubuntu 24.04 | gitleaks over the full Git history |

macOS 15 is the only supported operating system for tests and the first release. Other systems are not tested.
Do not suppress audit or secret-scan failures; track each known failure in an issue.

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
The native development build and Adobe Acrobat validation were checked manually ([results](docs/interoperability.md#manual-checks)). Visual review, production build, and installer tests remain to be performed.

## Architecture

The React renderer uses a narrow preload API. Electron owns native dialogs, file access, and signing.
The renderer receives document and certificate metadata, never private-key bytes or unrestricted filesystem APIs.
Context isolation and sandboxing are enabled. Navigation, new windows, and permission requests are blocked.

The [AutoFirma analysis](research/autofirma/ANALYSIS.md) remains a historical reference.
Its Java-bridge proposal was superseded by the Java-free direction. Decompiled AutoFirma code is not used by this application.
