# Development roadmap

Garabato currently implements local PDF signing with RSA PKCS#12 identities.
The issues below track the remaining work; they do not claim completed functionality.

Keep Java out of the application. Use native adapters only where system certificate stores or hardware require them.

Start with dependency risk, continuous integration, and independent PDF interoperability checks.
Each issue defines acceptance criteria and dependencies. Milestones have no promised delivery dates.

## 1. Reliable local PDF signing

- [#1: Resolve signing dependency risks before distribution](https://github.com/alberto-castano/garabato/issues/1)
- [#2: Add continuous integration for the supported toolchain](https://github.com/alberto-castano/garabato/issues/2)
- [#3: Validate PDF signatures with independent readers and FNMT-compatible fixtures](https://github.com/alberto-castano/garabato/issues/3)
- [#4: Add PDF preview and visible signature placement](https://github.com/alberto-castano/garabato/issues/4)
- [#5: Sign through macOS Keychain without exporting private keys](https://github.com/alberto-castano/garabato/issues/5)
- [#6: Preserve existing PDF signatures when adding another signature](https://github.com/alberto-castano/garabato/issues/6)
- [#7: Add signature inspection and certificate trust validation](https://github.com/alberto-castano/garabato/issues/7)
- [#8: Implement and validate explicit PAdES profiles and trusted timestamps](https://github.com/alberto-castano/garabato/issues/8)
- [#9: Move PDF parsing and signing off the Electron main thread](https://github.com/alberto-castano/garabato/issues/9)
- [#10: Complete accessible desktop UX and Spanish localization](https://github.com/alberto-castano/garabato/issues/10)
- [#11: Package and release signed desktop installers](https://github.com/alberto-castano/garabato/issues/11)

## 2. Government website compatibility

- [#12: Specify AutoFirma browser compatibility and target government services](https://github.com/alberto-castano/garabato/issues/12)
- [#13: Implement secure afirma protocol and local browser transport](https://github.com/alberto-castano/garabato/issues/13)
- [#14: Prove end-to-end compatibility with selected government services](https://github.com/alberto-castano/garabato/issues/14)

## 3. Extended formats and certificate providers

- [#15: Add CAdES, XAdES, XMLDSig, and FacturaE signing profiles](https://github.com/alberto-castano/garabato/issues/15)
- [#16: Add batch signing with per-document results and cancellation](https://github.com/alberto-castano/garabato/issues/16)
- [#17: Add Windows certificate stores, DNIe, and hardware token providers](https://github.com/alberto-castano/garabato/issues/17)
- [#18: Assess and implement ODF and OOXML document signing](https://github.com/alberto-castano/garabato/issues/18)

## Release scope

The first release targets local PDF signing on macOS. Government website replacement requires the second milestone and its published compatibility matrix.
Other operating systems, hardware, and document formats are supported only after their specific checks pass.

A public repository does not establish an open-source license. Select a license and third-party notices before distribution, as tracked in #11.
