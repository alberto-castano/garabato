# Garabato

An Electron, TypeScript, React, and shadcn/ui application for local PDF signing. No Java runtime or AutoFirma installation is required.

See the [development roadmap](docs/ROADMAP.md) for prioritized issues, acceptance criteria, and dependencies.

## First milestone

- Choose an unsigned PDF and an RSA `.p12` or `.pfx` certificate, or an RSA identity in the macOS Keychain.
- Unlock the certificate file, or select the Keychain identity, and review its identity before signing.
- Add a detached SHA-256/RSA CMS signature and save a new PDF.
- Keep the original file unchanged. Existing destinations are never overwritten.
- Clear certificate data after a successful save, session reset, or window close.

PDFs are limited to 25 MiB; certificate files to 2 MiB. The certificate needs one matching RSA private key in a protected PKCS#12 key bag.
Supported PKCS#12 encryption: PBES2 with AES or 3DES, and legacy SHA-1 3DES or RC2.

### macOS Keychain

"Find in Keychain" lists identities in the user's keychain search list that have an RSA private key and a certificate within its validity dates.
The private key stays in the Keychain. macOS asks the user to allow each use, and to unlock a locked keychain.
The signature embeds the signer certificate and the issuers that macOS finds locally. The helper never fetches certificates from the network.
Smart-card and token identities are not supported yet ([#17](https://github.com/alberto-castano/garabato/issues/17)).

## Development

Use Bun 1.4.0 (`packageManager` in package.json) and Node 24.14.1 (`.node-version`).

```sh
bun install --frozen-lockfile
bun run dev
```

`dev` and `build` first compile the Keychain helper with `swiftc` (Xcode Command Line Tools). `bun run build:keychain` compiles only the helper.

If Electron reports a missing binary after installation, run `node node_modules/electron/install.js`.

```sh
bun run typecheck
bun run lint
bun run test
```

Tests require OpenSSL 3.4 or later with the `cms` command and the legacy provider. They generate disposable certificates and verify signed bytes independently.
OpenSSL is a test dependency; the application does not invoke it.
On macOS, the system `openssl` is LibreSSL. Install Homebrew `openssl@3` and put its `bin` directory first on `PATH`.

Interoperability and Keychain tests also need Poppler `pdfsig`, NSS `certutil`, and `uvx` (`brew install poppler uv`).
Keychain tests compile the helper and use a temporary keychain file. They do not change the user's keychains or search list.
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
Packaging ([#11](https://github.com/alberto-castano/garabato/issues/11)) must copy `native/build/garabato-keychain` to the app's `Resources` folder and sign it with the app's identity.

## Current limits

This is a local signing milestone, not a complete AutoFirma replacement.
It rejects encrypted PDFs, XFA forms, PDFs with existing signatures, invalid certificate dates, and unsupported key containers.
It does not provide a visible signature stamp, certificate trust validation, revocation checks, timestamps, or full PAdES validation.
Windows certificate stores, DNIe, smart cards, hardware tokens, XAdES, CAdES, batch signing, and `afirma://` website integration are not implemented.

The certificate file password is retained in main-process memory until the certificate is cleared. It is never written to application storage.
JavaScript cannot guarantee that every copied string is erased from memory. Do not treat memory cleanup as secure erasure.
PDF parsing and signing currently run in the main process; large or complex inputs can pause the window.

See [dependency decisions and audit results](docs/dependencies.md).
The test suite checks cryptographic output, file preservation, session cleanup, IPC authorization, and UI state transitions.
The native development build and Adobe Acrobat validation were checked manually ([results](docs/interoperability.md#manual-checks)). Visual review, production build, and installer tests remain to be performed.

## Architecture

The React renderer uses a narrow preload API. Electron owns native dialogs, file access, and signing.
The renderer receives document and certificate metadata, never private-key bytes or unrestricted filesystem APIs.
Keychain identities reach the renderer as public metadata and a random reference. The reference is valid until the next listing or session reset.
Context isolation and sandboxing are enabled. Navigation, new windows, and permission requests are blocked.

Signing uses a certificate provider (`src/main/signing.ts`): a PKCS#12 file, or a Keychain identity (`src/main/keychain.ts`).
Keychain access runs in `garabato-keychain`, a Swift command-line helper (`native/keychain/main.swift`) that uses the macOS Security framework.
The main process starts it for each request and exchanges one JSON message on stdin and stdout. The helper returns certificates and signatures only. It has no command that exports a key.
macOS ties "Always Allow" to the helper's code signature. A rebuilt development helper therefore asks again.

The [AutoFirma analysis](research/autofirma/ANALYSIS.md) remains a historical reference.
Its Java-bridge proposal was superseded by the Java-free direction. Decompiled AutoFirma code is not used by this application.
