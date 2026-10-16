import {
  createHash,
  createPrivateKey,
  type KeyObject,
  X509Certificate,
} from "node:crypto";
import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFInvalidObject,
  PDFName,
  PDFNumber,
  type PDFObject,
  PDFStream,
  PDFString,
} from "@cantoo/pdf-lib";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import type { CertificateInfo } from "../shared/contracts";
import { signDetached } from "./cms";
import { type Pkcs12Contents, readPkcs12 } from "./pkcs12";

export const MAX_PDF_BYTES = 25 * 1024 * 1024;
export const MAX_P12_BYTES = 2 * 1024 * 1024;
// Room for a 16 KiB CMS signature, hex-encoded.
const SIGNATURE_HEX_LENGTH = 32768;

export type { CertificateInfo } from "../shared/contracts";

function checkSize(bytes: Buffer, limit: number, label: string): void {
  if (bytes.length === 0 || bytes.length > limit) {
    throw new Error(
      `${label} must contain data and be no larger than ${limit / 1024 / 1024} MiB.`,
    );
  }
}

async function loadUnsignedPdf(bytes: Buffer): Promise<PDFDocument> {
  checkSize(bytes, MAX_PDF_BYTES, "PDF");
  let document: PDFDocument;
  try {
    document = await PDFDocument.load(bytes, {
      updateMetadata: false,
      throwOnInvalidObject: true,
    });
  } catch {
    throw new Error("Cannot read this PDF. Select a valid, unencrypted PDF.");
  }
  if (document.isEncrypted)
    throw new Error("Encrypted PDFs are not supported.");
  if (document.getPageCount() === 0)
    throw new Error("The PDF must contain at least one page.");
  // pdf-lib's getForm() deletes XFA data. Reject it before any form access.
  const form = document.catalog.lookupMaybe(PDFName.of("AcroForm"), PDFDict);
  if (form?.has(PDFName.of("XFA"))) {
    throw new Error("XFA forms are not supported. Choose a standard PDF.");
  }

  // Walk direct objects too: a signature dictionary need not be an indirect object.
  const pending: PDFObject[] = document.context
    .enumerateIndirectObjects()
    .map(([, object]) => object);
  const visited = new Set<PDFObject>();
  while (pending.length > 0) {
    const object = pending.pop();
    if (!object || visited.has(object)) continue;
    visited.add(object);
    if (object instanceof PDFStream) pending.push(object.dict);
    if (object instanceof PDFDict) {
      if (
        object.has(PDFName.of("ByteRange")) ||
        object.get(PDFName.of("Type")) === PDFName.of("Sig")
      ) {
        throw new Error(
          "This PDF already contains a signature. Select an unsigned PDF.",
        );
      }
      pending.push(...object.values());
    } else if (object instanceof PDFArray) {
      pending.push(...object.asArray());
    }
  }
  return document;
}

export async function inspectPdf(pdf: Buffer): Promise<{ pageCount: number }> {
  return { pageCount: (await loadUnsignedPdf(pdf)).getPageCount() };
}

// X.500 attribute short names for display (RFC 4519).
const attributeNames: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.4": "SN",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.12": "title",
  "2.5.4.42": "GN",
  "2.5.4.97": "organizationIdentifier",
  "1.2.840.113549.1.9.1": "E",
};

function certificateName(name: pkijs.RelativeDistinguishedNames): string {
  return name.typesAndValues
    .flatMap(({ type, value }) =>
      value instanceof asn1js.BaseStringBlock
        ? [`${attributeNames[type] ?? type}=${value.getValue()}`]
        : [],
    )
    .join(", ");
}

function readCertificate(
  p12: Buffer,
  password: string,
): {
  info: CertificateInfo;
  signer: Buffer;
  certificates: Buffer[];
  key: KeyObject;
} {
  checkSize(p12, MAX_P12_BYTES, "Certificate file");
  const unreadable = new Error(
    "Cannot open the certificate. Check the password and use a supported RSA .p12 or .pfx file.",
  );
  let container: Pkcs12Contents;
  try {
    container = readPkcs12(p12, password);
  } catch {
    throw unreadable;
  }
  if (container.keys.length !== 1)
    throw new Error(
      "The certificate file must contain exactly one private key.",
    );
  const [keyBag] = container.keys;
  let key: KeyObject;
  let certificates: X509Certificate[];
  try {
    key = createPrivateKey({ key: keyBag.pkcs8, format: "der", type: "pkcs8" });
    certificates = container.certificates.map(
      (der) => new X509Certificate(der),
    );
  } catch {
    throw unreadable;
  }
  if (key.asymmetricKeyType !== "rsa")
    throw new Error("Only RSA private keys are supported.");
  if (!keyBag.encrypted) {
    throw new Error(
      "This private-key container is unsupported. Export a password-protected .p12 or .pfx file.",
    );
  }
  const matching = certificates.filter((certificate) =>
    certificate.checkPrivateKey(key),
  );
  if (matching.length !== 1)
    throw new Error("The private key must match exactly one certificate.");
  const signer = matching[0].raw;
  let certificate: pkijs.Certificate;
  try {
    certificate = pkijs.Certificate.fromBER(new Uint8Array(signer));
  } catch {
    throw unreadable;
  }
  const notBefore = certificate.notBefore.value;
  const notAfter = certificate.notAfter.value;
  const now = Date.now();
  if (now < notBefore.getTime())
    throw new Error("The certificate is not valid yet.");
  if (now > notAfter.getTime()) throw new Error("The certificate has expired.");
  return {
    info: {
      subject: certificateName(certificate.subject),
      issuer: certificateName(certificate.issuer),
      validFrom: notBefore.toISOString(),
      validTo: notAfter.toISOString(),
      fingerprint: createHash("sha256").update(signer).digest("hex"),
    },
    signer,
    // Embed the whole container chain, as Adobe and EU validators expect.
    certificates: container.certificates,
    key,
  };
}

export function inspectCertificate(
  p12: Buffer,
  password: string,
): CertificateInfo {
  return readCertificate(p12, password).info;
}

export async function signPdf(
  pdf: Buffer,
  p12: Buffer,
  password: string,
): Promise<Buffer> {
  const document = await loadUnsignedPdf(pdf);
  const certificate = readCertificate(p12, password);
  try {
    const fieldNames = new Set(
      document
        .getForm()
        .getFields()
        // The new field is at the root, so also reserve existing group names.
        .map((field) => field.getName().split(".")[0]),
    );
    let signatureName = "GarabatoSignature";
    for (let suffix = 2; fieldNames.has(signatureName); suffix += 1) {
      signatureName = `GarabatoSignature${suffix}`;
    }
    const signingTime = new Date();
    // Fixed-width placeholders: filling them keeps the serialized PDF length.
    const byteRangePlaceholder = `/ByteRange [0 ${"9".repeat(10)} ${"9".repeat(10)} ${"9".repeat(10)}]`;
    const contentsPlaceholder = `/Contents <${"0".repeat(SIGNATURE_HEX_LENGTH)}>`;
    // Identity comes from the embedded certificate, so the dictionary has no
    // text metadata. Raw bytes stop pdf-lib from reformatting it or moving it
    // into an object stream.
    const signatureBody = [
      "<<",
      "/Type /Sig",
      "/Filter /Adobe.PPKLite",
      "/SubFilter /adbe.pkcs7.detached",
      byteRangePlaceholder,
      contentsPlaceholder,
      `/M ${PDFString.fromDate(signingTime).toString()}`,
      "/Prop_Build << /Filter << /Name /Adobe.PPKLite >> /App << /Name /Garabato >> >>",
      ">>",
    ].join("\n");
    const { context } = document;
    const signatureRef = context.register(
      PDFInvalidObject.of(Buffer.from(signatureBody, "latin1")),
    );
    const page = document.getPage(0);
    const widget = context.register(
      context.obj({
        Type: "Annot",
        Subtype: "Widget",
        FT: "Sig",
        Rect: [0, 0, 0, 0],
        V: signatureRef,
        T: PDFString.of(signatureName),
        F: 4, // Print
        P: page.ref,
        // An empty appearance stream, required for PDF/A.
        AP: {
          N: context.register(
            context.formXObject([], { BBox: [0, 0, 0, 0], Resources: {} }),
          ),
        },
      }),
    );
    // lookupMaybe() resolves indirect arrays, so existing trees stay in place.
    const annotations = page.node.lookupMaybe(PDFName.of("Annots"), PDFArray);
    if (annotations) annotations.push(widget);
    else page.node.set(PDFName.of("Annots"), context.obj([widget]));
    let form = document.catalog.lookupMaybe(PDFName.of("AcroForm"), PDFDict);
    if (!form) {
      form = context.obj({});
      document.catalog.set(PDFName.of("AcroForm"), context.register(form));
    }
    const fields = form.lookupMaybe(PDFName.of("Fields"), PDFArray);
    if (fields) fields.push(widget);
    else form.set(PDFName.of("Fields"), context.obj([widget]));
    // Add SignaturesExist (1) and AppendOnly (2) to any existing flags.
    const flags = form.lookupMaybe(PDFName.of("SigFlags"), PDFNumber);
    form.set(
      PDFName.of("SigFlags"),
      PDFNumber.of((flags?.asNumber() ?? 0) | 3),
    );
    const prepared = Buffer.from(
      await document.save({ useObjectStreams: false }),
    );
    // Match the complete generated object, including its reference, not arbitrary
    // /ByteRange text elsewhere in an input string or stream.
    const header = `${signatureRef.objectNumber} ${signatureRef.generationNumber} obj\n`;
    const signatureObject = Buffer.from(
      `${header}${signatureBody}\nendobj`,
      "latin1",
    );
    const offset = prepared.indexOf(signatureObject);
    if (offset < 0 || prepared.indexOf(signatureObject, offset + 1) !== -1) {
      throw new Error("Signature object is not unique");
    }
    const bodyOffset = offset + header.length;
    // start is the "<" of the signature slot; end follows its ">".
    const start =
      bodyOffset +
      signatureBody.indexOf(contentsPlaceholder) +
      "/Contents ".length;
    const end = start + SIGNATURE_HEX_LENGTH + 2;
    const byteRange = `/ByteRange [0 ${start} ${end} ${prepared.length - end}]`;
    if (byteRange.length > byteRangePlaceholder.length)
      throw new Error("Byte range is too long");
    prepared.write(
      byteRange.padEnd(byteRangePlaceholder.length, " "),
      bodyOffset + signatureBody.indexOf(byteRangePlaceholder),
      "ascii",
    );
    const signature = signDetached({
      ...certificate,
      content: Buffer.concat([
        prepared.subarray(0, start),
        prepared.subarray(end),
      ]),
      signingTime,
    });
    const hex = signature.toString("hex");
    if (hex.length > SIGNATURE_HEX_LENGTH)
      throw new Error("Signature is too large");
    prepared.write(hex.padEnd(SIGNATURE_HEX_LENGTH, "0"), start + 1, "ascii");
    return prepared;
  } catch {
    throw new Error(
      "Signing failed. This PDF or certificate is not supported.",
    );
  }
}
