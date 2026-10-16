# AutoFirma investigation for Garabato

> Historical investigation. The user subsequently chose a Java-free Electron/TypeScript application with shadcn/ui.
> The Java-bridge recommendation below is superseded. See the current [README](../../README.md).
> Evidence, decompiled files, downloaded source, and tools are local-only and excluded from Git.
> Links to those files work only in the original research workspace.

## Outcome

An Electron interface with a separate Java signing process is the recommended starting architecture.
Reuse the maintained signing libraries through a small bridge. Replace Swing interactions with explicit bridge events.
Treat browser compatibility as a separate deliverable from local document signing.

This is a static investigation of the installed application. No signing operation or certificate enumeration was performed.
The installed application, system trust settings, and protocol registration were not changed.
No Electron application was implemented or tested during this investigation.

## Installed application

- Location: `/Applications/Autofirma.app`.
- Bundle version: `1.9`, build `1`.
- Identifier: `es.gob.afirma.simpleafirma.osx`.
- Registered URL scheme: `afirma`.
- Launcher: universal Mach-O, with x86_64 and arm64 code.
- Bundled runtime: Eclipse Temurin `21.0.6+7-LTS`, aarch64.
- Application JAR: `Contents/Resources/JAR/autofirma.jar`, 49,545,879 bytes.
- JAR SHA-256: `bd265f7597ee6814634f7b8b247f96eb2a0db61b602a75d37086a4a84c1f1259`.
- Main class: `es.gob.afirma.standalone.SimpleAfirma`.
- JAR class count: 19,056, including bundled dependencies.

Evidence: [inventory](evidence/inventory.json), [manifest](evidence/manifest-main.txt),
[JAR entries](evidence/jar-entries.txt), and [dependency metadata](evidence/dependencies.json).
Runtime details come from `Contents/Resources/Home/release`.
Launcher strings point to that runtime and the application JAR.
The native launcher was inspected with `file` and `strings`; it was not decompiled.

The manifest reports specification version `1.8` and implementation version `build01`.
Therefore, bundle version alone does not prove an exact source revision.

## Recovered code and provenance

CFR 0.152 processed 561 selected class files into 412 Java files.
The selection covers standalone application code, protocol parsing, keystore code, and signer interfaces/factory.
Inner classes explain part of the difference between input and output counts.
This is a targeted decompilation, not a decompilation of all bundled dependencies or cryptographic implementations.

The official repository provides source, so decompiled code should serve as evidence rather than the implementation base.
Selected source files were downloaded from tag `v1.9`, commit `1f29aa7a2aae8eda40a70fed79b0428153c78df8`.
See [source provenance](upstream/SOURCE.txt) and the [official repository](https://github.com/ctt-gob-es/clienteafirma).
This tag has not been proven to reproduce the installed JAR.

CFR reported two material limitations:

- `CommandLineLauncher.processCommandLine`: decompilation failed.
- `ProtocolInvocationLauncherBatch.processBatch`: control flow could not be fully structured.

See [CFR summary](decompiled/summary.txt). Official source helps interpret these methods, but does not establish binary equivalence.
Other recovered methods were not exhaustively checked for decompiler errors.

To repeat the decompilation from this workspace:

```sh
/Applications/Autofirma.app/Contents/Resources/Home/bin/java \
  -jar research/autofirma/tools/cfr-0.152.jar \
  research/autofirma/evidence/analysis-classes.jar \
  --extraclasspath /Applications/Autofirma.app/Contents/Resources/JAR/autofirma.jar \
  --outputdir research/autofirma/decompiled \
  --silent true
```

Tool source: [CFR](https://www.benf.org/other/cfr/). The extracted analysis JAR is not an executable application.

## Interfaces found

### Desktop and command line

The native launcher starts Java. `SimpleAfirma.main` dispatches into command-line or graphical handling.
It also initializes logging, proxy settings, and trust configuration before command-line dispatch.
Its secure-connection branch can contact `https://www.google.es/` during initialization.
This is one reason to call library APIs through a dedicated bridge instead of embedding the full launcher.

Evidence: [installed SimpleAfirma](decompiled/es/gob/afirma/standalone/SimpleAfirma.java).

The installed command enum exposes `listaliases`, `sign`, `cosign`, `countersign`, `verify`, and `batchsign`.
Parameters include `-store`, `-alias`, `-password`, `-format`, `-gui`, `-certgui`, and `-xml`.
These form a useful experimental interface, but not a complete product API.
Do not pass passwords through process arguments in the new application.

Evidence: [commands](decompiled/es/gob/afirma/standalone/CommandLineCommand.java),
[parameters](decompiled/es/gob/afirma/standalone/CommandLineParameters.java),
and [upstream command launcher](upstream/afirma-simple/src/main/java/es/gob/afirma/standalone/CommandLineLauncher.java).
The upstream launcher supports macOS, Windows, Mozilla/NSS, PKCS#12, PKCS#11, and DNIe store choices.
Those choices have not been exercised on this machine.

### Browser integration

The installed protocol dispatcher recognizes `websocket`, `service`, `batch`, `selectcert`, `save`, `signandsave`,
`sign`, `cosign`, `countersign`, and `load` operations under `afirma://`.
The WebSocket manager supports versions 3 and 4 and configures TLS through `SecureSocketUtils`.
Version 4 checks the remote address and compares the session identifier when one was supplied.
It also handles echo messages and uses a longer connection timeout for batch requests.

Evidence: [dispatcher](decompiled/es/gob/afirma/standalone/protocol/ProtocolInvocationLauncher.java),
[WebSocket manager](decompiled/es/gob/afirma/standalone/protocol/AfirmaWebSocketServerManager.java),
and [version 4 handler](decompiled/es/gob/afirma/standalone/protocol/AfirmaWebSocketServerV4.java).

A replacement must preserve request parsing, response encodings, cancellation, error codes, and session behavior.
Registering the URL scheme alone will not establish compatibility with government websites.
The legacy service and intermediate-server paths need further analysis and fixtures.
No end-to-end website compatibility claim follows from this static inspection.

### Signing and certificate access

`AOSignerFactory` maps format names to implementations for PDF/PAdES, CAdES, XAdES, XMLDSig, FacturaE,
ODF, OOXML, and other variants, including several three-phase variants.
Factory entries establish dispatch support, not that every format was tested or every optional implementation is present.

Evidence: [signer factory](decompiled/es/gob/afirma/core/signers/AOSignerFactory.java).

The protocol signing flow calls `sign`, `cosign`, or `countersign` with a private-key entry and certificate chain.
The same flow invokes `AOUIFactory` for file selection, passwords, and confirmations.
This coupling means that wrapping the existing application will retain Java dialogs.

Evidence: [signing flow](decompiled/es/gob/afirma/standalone/protocol/ProtocolInvocationLauncherSign.java)
and [keystore manager](decompiled/es/gob/afirma/keystores/AOKeyStoreManager.java).

## Proposed implementation

Use Electron, TypeScript, and React for the interface. Use Bun for the new JavaScript project.
Use Maven for a Java bridge built against a selected upstream library version.
Dependency versions and release health still need checking when implementation starts.

Keep the renderer sandboxed, disable Node integration, and enable context isolation.
Expose narrow preload methods. Validate IPC senders and payloads in the main process.
These choices follow [Electron's security guidance](https://www.electronjs.org/docs/latest/tutorial/security).

The main process should own file dialogs, approved file access, bridge lifetime, and operation cancellation.
Use framed messages over child-process stdin/stdout for private bridge communication.
Reserve stderr for diagnostic output without document content or credentials.
Do not expose the internal bridge as the browser-facing protocol service.

Start the bridge contract with `listCertificates`, `inspectDocument`, `signDocument`, `verifySignature`, and `cancel`.
Return opaque certificate references and public metadata. Keep private keys inside the signing process or key provider.
Bind user confirmation to the selected document, certificate, and signing parameters.
Represent password requests and other required decisions as explicit events.
Do not promise that operating-system or hardware-token prompts can all be replaced.

### Delivery sequence

1. Prove local PDF signing with a disposable test certificate and an independently verified output.
2. Add certificate selection, PDF inspection, signature placement, progress, cancellation, and clear errors in Electron.
3. Verify macOS Keychain integration and interruption behavior with explicit test fixtures.
4. Add CAdES, XAdES, batch operations, and the required certificate providers.
5. Add browser protocol compatibility against captured synthetic requests and controlled integration pages.
6. Package a pinned Java runtime and bridge; verify signing, notarization, updates, and rollback.

This sequence is a proposal. It does not imply completed implementation or a delivery estimate.

## Validation needed before replacement

- Validate generated signatures with an independent implementation; compare semantics rather than exact signature bytes.
- Cover malformed inputs, unsupported algorithms, expired certificates, cancellation, and wrong passwords.
- Test already-signed PDFs, visible signatures, and preservation of existing signatures.
- Distinguish cryptographic integrity from certificate trust, revocation, and timestamp validation in the UI.
- Test protocol session mismatches, parallel requests, oversized input, cancellation, and error responses.
- Test each claimed operating system and hardware provider. This investigation only inspected a macOS installation.

## Distribution inputs

The upstream release includes GPL and EUPL notices plus notices for bundled components.
Copies are in [upstream/license](upstream/license/), including `autofirma-LICENSE.txt`.
Do not assume an Electron process boundary removes upstream distribution requirements.
Select the distribution model and dependency set before bundling upstream code for release.
This investigation records the notices; it does not determine licensing compatibility for a future product.

## Remaining unknowns

- Exact source revision and reproducibility of the installed JAR.
- Which government websites, operating systems, and certificate providers are required for the first release.
- Complete legacy socket and intermediate-server contracts.
- Runtime behavior of the proposed bridge and the amount of UI coupling inside each selected signing path.
- Startup cost and memory use of Electron plus Java; neither was benchmarked.

The next concrete implementation milestone is a local PDF signing bridge with disposable credentials and independent verification.
