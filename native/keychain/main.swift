// garabato-keychain: lists macOS signing identities and signs data with their
// private keys. Keys never leave the Keychain; macOS shows its own access prompt.
//
// Protocol: one JSON request on stdin, one JSON response on stdout.
//   {"command":"list"}
//     -> {"ok":true,"identities":[{"certificates":["<base64 DER>", ...]}]}
//        The signer certificate is first, followed by the chain macOS found.
//   {"command":"sign","fingerprint":"<SHA-256 hex of signer DER>","data":"<base64>"}
//     -> {"ok":true,"signature":"<base64>"}   RSA PKCS#1 v1.5 with SHA-256
//   Failures -> {"ok":false,"code":"<code>","status":<OSStatus>}
// Optional request fields, used by tests: "keychain" (path of the only keychain
// to search) and "interactive" (false makes macOS fail instead of prompting).

import CryptoKit
import Foundation
import Security

struct Request: Decodable {
  let command: String
  let fingerprint: String?
  let data: String?
  let keychain: String?
  let interactive: Bool?
}

let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256

func respond(_ value: [String: Any]) -> Never {
  let output = try! JSONSerialization.data(withJSONObject: value)
  FileHandle.standardOutput.write(output)
  exit(value["ok"] as? Bool == true ? 0 : 1)
}

func fail(_ code: String, _ status: OSStatus = errSecParam) -> Never {
  respond(["ok": false, "code": code, "status": Int(status)])
}

func fail(_ status: OSStatus) -> Never {
  switch status {
  case errSecUserCanceled: fail("canceled", status)
  case errSecAuthFailed: fail("denied", status)
  case errSecInteractionNotAllowed: fail("interaction-not-allowed", status)
  case errSecItemNotFound: fail("not-found", status)
  case errSecNoSuchKeychain, errSecInvalidKeychain: fail("no-keychain", status)
  default: fail("failed", status)
  }
}

func check(_ status: OSStatus) {
  if status != errSecSuccess { fail(status) }
}

func fingerprint(_ certificate: SecCertificate) -> String {
  SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
    .map { String(format: "%02x", $0) }.joined()
}

/// Identities whose private key can make an RSA PKCS#1 v1.5 SHA-256 signature.
func identities(_ request: Request) -> [(SecIdentity, SecCertificate, SecKey)] {
  var query: [CFString: Any] = [
    kSecClass: kSecClassIdentity,
    kSecMatchLimit: kSecMatchLimitAll,
    kSecReturnRef: true,
  ]
  if let path = request.keychain {
    var keychain: SecKeychain?
    check(SecKeychainOpen(path, &keychain))
    query[kSecMatchSearchList] = [keychain!]
  }
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  if status == errSecItemNotFound { return [] }
  check(status)
  return (result as? [SecIdentity] ?? []).compactMap { identity in
    var certificate: SecCertificate?
    var key: SecKey?
    guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
      SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess,
      let certificate, let key, SecKeyIsAlgorithmSupported(key, .sign, algorithm)
    else { return nil }
    return (identity, certificate, key)
  }
}

/// Whether the file keychain that holds key is locked.
func isLocked(_ key: SecKey) -> Bool {
  var keychain: SecKeychain?
  var state: SecKeychainStatus = 0
  // File-keychain keys are also keychain items.
  let item = unsafeBitCast(key, to: SecKeychainItem.self)
  guard SecKeychainItemCopyKeychain(item, &keychain) == errSecSuccess, let keychain,
    SecKeychainGetStatus(keychain, &state) == errSecSuccess
  else { return false }
  return state & SecKeychainStatus(kSecUnlockStateStatus) == 0
}

/// The signer certificate followed by any issuers macOS finds locally.
func chain(_ certificate: SecCertificate) -> [Data] {
  var trust: SecTrust?
  guard SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
    let trust
  else { return [SecCertificateCopyData(certificate) as Data] }
  // Never fetch missing issuers from the network.
  SecTrustSetNetworkFetchAllowed(trust, false)
  // The chain is built even when it is not trusted.
  _ = SecTrustEvaluateWithError(trust, nil)
  let certificates = SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? [certificate]
  return certificates.map { SecCertificateCopyData($0) as Data }
}

guard
  let request = try? JSONDecoder().decode(
    Request.self, from: FileHandle.standardInput.readDataToEndOfFile())
else { fail("bad-request") }
if request.interactive == false { check(SecKeychainSetUserInteractionAllowed(false)) }

switch request.command {
case "list":
  var seen = Set<String>()
  let found = identities(request).compactMap { _, certificate, _ -> [String: Any]? in
    guard seen.insert(fingerprint(certificate)).inserted else { return nil }
    return ["certificates": chain(certificate).map { $0.base64EncodedString() }]
  }
  respond(["ok": true, "identities": found])
case "sign":
  guard let wanted = request.fingerprint?.lowercased(),
    let encoded = request.data, let data = Data(base64Encoded: encoded)
  else { fail("bad-request") }
  guard let (_, _, key) = identities(request).first(where: { fingerprint($0.1) == wanted })
  else { fail("not-found", errSecItemNotFound) }
  var error: Unmanaged<CFError>?
  guard let signature = SecKeyCreateSignature(key, algorithm, data as CFData, &error) else {
    let status = OSStatus(
      truncatingIfNeeded: error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? -1)
    // A locked keychain and a refused key both report errSecAuthFailed.
    if status != errSecUserCanceled && isLocked(key) { fail("locked", status) }
    fail(status)
  }
  respond(["ok": true, "signature": (signature as Data).base64EncodedString()])
default:
  fail("bad-request")
}
