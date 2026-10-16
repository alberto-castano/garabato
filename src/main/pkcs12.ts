import {
  createDecipheriv,
  createHash,
  createHmac,
  pbkdf2Sync,
  timingSafeEqual,
} from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { rc2DecryptCbc } from "./rc2";

// Bounds key-derivation work for hostile files. Common exports use 2,048 to 600,000.
const MAX_ITERATIONS = 1_000_000;

const oids = {
  data: "1.2.840.113549.1.7.1",
  encryptedData: "1.2.840.113549.1.7.6",
  x509Certificate: "1.2.840.113549.1.9.22.1",
  pbes2: "1.2.840.113549.1.5.13",
  pbkdf2: "1.2.840.113549.1.5.12",
  hmacWithSha1: "1.2.840.113549.2.7",
};

const digests: Record<string, string> = {
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.4": "sha224",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};

const prfs: Record<string, string> = {
  [oids.hmacWithSha1]: "sha1",
  "1.2.840.113549.2.8": "sha224",
  "1.2.840.113549.2.9": "sha256",
  "1.2.840.113549.2.10": "sha384",
  "1.2.840.113549.2.11": "sha512",
};

// PBES2 encryption schemes: Node cipher name and key length.
const pbes2Ciphers: Record<string, [string, number]> = {
  "2.16.840.1.101.3.4.1.2": ["aes-128-cbc", 16],
  "2.16.840.1.101.3.4.1.22": ["aes-192-cbc", 24],
  "2.16.840.1.101.3.4.1.42": ["aes-256-cbc", 32],
  "1.2.840.113549.3.7": ["des-ede3-cbc", 24],
};

// RFC 7292 appendix C password-based encryption with SHA-1.
const pkcs12Ciphers: Record<
  string,
  { keyLength: number; cipher: string } | { keyLength: number; rc2: number }
> = {
  "1.2.840.113549.1.12.1.3": { keyLength: 24, cipher: "des-ede3-cbc" },
  "1.2.840.113549.1.12.1.5": { keyLength: 16, rc2: 128 },
  "1.2.840.113549.1.12.1.6": { keyLength: 5, rc2: 40 },
};

export interface Pkcs12Contents {
  /** Decrypted PKCS#8 PrivateKeyInfo DER, and whether the bag was shrouded. */
  keys: { pkcs8: Buffer; encrypted: boolean }[];
  /** X.509 certificate DER, unchanged. */
  certificates: Buffer[];
}

function octets(value: unknown): Buffer {
  if (!(value instanceof asn1js.OctetString))
    throw new Error("Expected OCTET STRING");
  // getValue() also joins constructed BER strings.
  return Buffer.from(value.getValue());
}

// EncryptedContentInfo stores [0] IMPLICIT OCTET STRING; pkijs only retags it.
function implicitOctets(value: unknown): Buffer {
  if (value instanceof asn1js.Constructed)
    return Buffer.concat(value.valueBlock.value.map(implicitOctets));
  if (value instanceof asn1js.Primitive)
    return Buffer.from(value.valueBlock.valueHexView);
  return octets(value);
}

function iterations(count: number): number {
  if (!Number.isSafeInteger(count) || count < 1 || count > MAX_ITERATIONS) {
    throw new Error("Unsupported iteration count");
  }
  return count;
}

/** RFC 7292 appendix B.2 key derivation. ID 1 is a key, 2 an IV, 3 a MAC key. */
export function pkcs12Kdf(
  digest: string,
  password: string,
  salt: Buffer,
  id: 1 | 2 | 3,
  count: number,
  length: number,
): Buffer {
  const v = digest === "sha384" || digest === "sha512" ? 128 : 64;
  const fill = (data: Buffer) => {
    const output = Buffer.alloc(v * Math.ceil(data.length / v));
    for (let i = 0; i < output.length; i += 1)
      output[i] = data[i % data.length];
    return output;
  };
  // BMPString with a two-byte terminator.
  const input = Buffer.concat([
    fill(salt),
    fill(Buffer.from(`${password}\0`, "utf16le").swap16()),
  ]);
  const prefix = Buffer.alloc(v, id);
  const blocks: Buffer[] = [];
  for (let produced = 0; produced < length; ) {
    let a = createHash(digest).update(prefix).update(input).digest();
    for (let n = 1; n < count; n += 1)
      a = createHash(digest).update(a).digest();
    blocks.push(a);
    produced += a.length;
    if (produced >= length) break;
    const b = fill(a);
    for (let offset = 0; offset < input.length; offset += v) {
      let carry = 1;
      for (let i = v - 1; i >= 0; i -= 1) {
        carry += input[offset + i] + b[i];
        input[offset + i] = carry & 0xff;
        carry >>>= 8;
      }
    }
  }
  return Buffer.concat(blocks).subarray(0, length);
}

function decipher(name: string, key: Buffer, iv: Buffer, data: Buffer) {
  const cipher = createDecipheriv(name, key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function decrypt(
  algorithm: pkijs.AlgorithmIdentifier,
  data: Buffer,
  password: string,
): Buffer {
  const legacy = pkcs12Ciphers[algorithm.algorithmId];
  if (legacy) {
    const params = algorithm.algorithmParams;
    const [salt, count] =
      params instanceof asn1js.Sequence ? params.valueBlock.value : [];
    if (!(count instanceof asn1js.Integer))
      throw new Error("Invalid PBE parameters");
    const derive = (id: 1 | 2, length: number) =>
      pkcs12Kdf(
        "sha1",
        password,
        octets(salt),
        id,
        iterations(count.valueBlock.valueDec),
        length,
      );
    const key = derive(1, legacy.keyLength);
    const iv = derive(2, 8);
    return "rc2" in legacy
      ? rc2DecryptCbc(key, legacy.rc2, iv, data)
      : decipher(legacy.cipher, key, iv, data);
  }
  if (algorithm.algorithmId !== oids.pbes2)
    throw new Error("Unsupported encryption");
  const pbes2 = new pkijs.PBES2Params({ schema: algorithm.algorithmParams });
  if (pbes2.keyDerivationFunc.algorithmId !== oids.pbkdf2)
    throw new Error("Unsupported key derivation");
  const kdf = new pkijs.PBKDF2Params({
    schema: pbes2.keyDerivationFunc.algorithmParams,
  });
  const scheme = pbes2Ciphers[pbes2.encryptionScheme.algorithmId];
  const prf = prfs[kdf.prf?.algorithmId ?? oids.hmacWithSha1];
  if (!scheme || !prf) throw new Error("Unsupported encryption");
  const [cipher, keyLength] = scheme;
  if (kdf.keyLength !== undefined && kdf.keyLength !== keyLength)
    throw new Error("Invalid key length");
  // PBES2 takes the password as UTF-8, unlike the BMPString PKCS#12 KDF.
  const key = pbkdf2Sync(
    Buffer.from(password, "utf8"),
    octets(kdf.salt),
    iterations(kdf.iterationCount),
    keyLength,
    prf,
  );
  return decipher(
    cipher,
    key,
    octets(pbes2.encryptionScheme.algorithmParams),
    data,
  );
}

function verifyMac(mac: pkijs.MacData, content: Buffer, password: string) {
  const digest = digests[mac.mac.digestAlgorithm.algorithmId];
  if (!digest) throw new Error("Unsupported MAC");
  const expected = octets(mac.mac.digest);
  const key = pkcs12Kdf(
    digest,
    password,
    octets(mac.macSalt),
    3,
    iterations(mac.iterations ?? 1),
    createHash(digest).digest().length,
  );
  const actual = createHmac(digest, key).update(content).digest();
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected))
    throw new Error("PKCS#12 integrity check failed");
}

function collect(
  bags: pkijs.SafeBag[],
  password: string,
  contents: Pkcs12Contents,
): void {
  for (const { bagValue } of bags) {
    if (bagValue instanceof pkijs.PKCS8ShroudedKeyBag) {
      contents.keys.push({
        pkcs8: decrypt(
          bagValue.encryptionAlgorithm,
          octets(bagValue.encryptedData),
          password,
        ),
        encrypted: true,
      });
    } else if (bagValue instanceof pkijs.PrivateKeyInfo) {
      contents.keys.push({
        pkcs8: Buffer.from(bagValue.toSchema().toBER()),
        encrypted: false,
      });
    } else if (
      bagValue instanceof pkijs.CertBag &&
      bagValue.certId === oids.x509Certificate
    ) {
      contents.certificates.push(octets(bagValue.certValue));
    } else if (bagValue instanceof pkijs.SafeContents) {
      collect(bagValue.safeBags, password, contents);
    }
    // CRL, secret, and other certificate types are not needed for signing.
  }
}

/**
 * Reads a password-integrity PKCS#12 file (RFC 7292). Verifies the MAC when
 * present and decrypts PBES2 (AES, 3DES) and legacy SHA-1 3DES or RC2 content.
 */
export function readPkcs12(der: Buffer, password: string): Pkcs12Contents {
  const pfx = pkijs.PFX.fromBER(new Uint8Array(der));
  if (pfx.authSafe.contentType !== oids.data)
    throw new Error("Unsupported PKCS#12 integrity mode");
  const authSafe = octets(pfx.authSafe.content);
  if (pfx.macData) verifyMac(pfx.macData, authSafe, password);
  const contents: Pkcs12Contents = { keys: [], certificates: [] };
  for (const info of pkijs.AuthenticatedSafe.fromBER(new Uint8Array(authSafe))
    .safeContents) {
    let safe: Buffer;
    if (info.contentType === oids.data) {
      safe = octets(info.content);
    } else if (info.contentType === oids.encryptedData) {
      const { encryptedContentInfo } = new pkijs.EncryptedData({
        schema: info.content,
      });
      safe = decrypt(
        encryptedContentInfo.contentEncryptionAlgorithm,
        implicitOctets(encryptedContentInfo.encryptedContent),
        password,
      );
    } else {
      throw new Error("Unsupported PKCS#12 content");
    }
    collect(
      pkijs.SafeContents.fromBER(new Uint8Array(safe)).safeBags,
      password,
      contents,
    );
  }
  return contents;
}
