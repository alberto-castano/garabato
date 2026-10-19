import { createHash } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

const oids = {
  data: "1.2.840.113549.1.7.1",
  signedData: "1.2.840.113549.1.7.2",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingTime: "1.2.840.113549.1.9.5",
  sha256: "2.16.840.1.101.3.4.2.1",
  rsaEncryption: "1.2.840.113549.1.1.1",
};

function algorithm(algorithmId: string): pkijs.AlgorithmIdentifier {
  return new pkijs.AlgorithmIdentifier({
    algorithmId,
    algorithmParams: new asn1js.Null(),
  });
}

function attribute(type: string, value: asn1js.AsnType): pkijs.Attribute {
  return new pkijs.Attribute({ type, values: [value] });
}

/**
 * Creates a detached CMS SignedData (RFC 5652) for adbe.pkcs7.detached with
 * SHA-256 and RSA PKCS#1 v1.5. Certificates are DER and embedded unchanged.
 * sign returns the RSA PKCS#1 v1.5 SHA-256 signature of its input.
 */
export async function signDetached(options: {
  content: Buffer;
  signer: Buffer;
  certificates: Buffer[];
  sign: (data: Buffer) => Promise<Buffer>;
  signingTime: Date;
}): Promise<Buffer> {
  const signer = pkijs.Certificate.fromBER(new Uint8Array(options.signer));
  // EU validators expect this attribute order.
  const signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      attribute(
        oids.contentType,
        new asn1js.ObjectIdentifier({ value: oids.data }),
      ),
      attribute(
        oids.signingTime,
        new asn1js.UTCTime({ valueDate: options.signingTime }),
      ),
      attribute(
        oids.messageDigest,
        new asn1js.OctetString({
          valueHex: createHash("sha256").update(options.content).digest(),
        }),
      ),
    ],
  });
  // RFC 5652 section 5.4: sign the attributes with an explicit SET OF tag.
  const signedBytes = Buffer.from(signedAttrs.toSchema().toBER());
  signedBytes[0] = 0x31;
  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    // The parsed issuer keeps its original DER, including multi-valued RDNs.
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: signer.issuer,
      serialNumber: signer.serialNumber,
    }),
    digestAlgorithm: algorithm(oids.sha256),
    signedAttrs,
    signatureAlgorithm: algorithm(oids.rsaEncryption),
    signature: new asn1js.OctetString({
      valueHex: await options.sign(signedBytes),
    }),
  });
  const signedData = new pkijs.SignedData({
    version: 1,
    digestAlgorithms: [algorithm(oids.sha256)],
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: oids.data,
    }),
    certificates: options.certificates.map((der) =>
      pkijs.Certificate.fromBER(new Uint8Array(der)),
    ),
    signerInfos: [signerInfo],
  });
  return Buffer.from(
    new pkijs.ContentInfo({
      contentType: oids.signedData,
      content: signedData.toSchema(),
    })
      .toSchema()
      .toBER(),
  );
}
