import {
  createHash,
  createPrivateKey,
  type KeyObject,
  X509Certificate,
} from "node:crypto";
import { pdflibAddPlaceholder } from "@signpdf/placeholder-pdf-lib";
import * as asn1js from "asn1js";
import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFName,
  PDFNumber,
  type PDFObject,
  PDFRef,
  PDFStream,
  PDFString,
} from "pdf-lib";
import * as pkijs from "pkijs";
import type { CertificateInfo } from "../shared/contracts";
import { signDetached } from "./cms";
import { type Pkcs12Contents, readPkcs12 } from "./pkcs12";

export const MAX_PDF_BYTES = 25 * 1024 * 1024;
export const MAX_P12_BYTES = 2 * 1024 * 1024;

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
    // The placeholder helper uses get(), not lookup(), for these form entries.
    // Resolve indirect objects so it preserves the existing field tree and flags.
    const form = document.catalog.lookupMaybe(PDFName.of("AcroForm"), PDFDict);
    if (form) {
      const fields = form.lookupMaybe(PDFName.of("Fields"), PDFArray);
      const flags = form.lookupMaybe(PDFName.of("SigFlags"), PDFNumber);
      if (fields) form.set(PDFName.of("Fields"), fields);
      if (flags) form.set(PDFName.of("SigFlags"), flags);
    }
    const signingTime = new Date();
    pdflibAddPlaceholder({
      pdfDoc: document,
      reason: "",
      contactInfo: "",
      location: "",
      // Identity comes from the embedded signing certificate. The helper's
      // PDFString.of(name) does not escape PDF syntax or encode Unicode safely.
      name: "",
      signingTime,
      signatureLength: 32768,
      appName: "Garabato",
    });
    const updatedForm = document.catalog.lookup(
      PDFName.of("AcroForm"),
      PDFDict,
    );
    const updatedFields = updatedForm.lookup(PDFName.of("Fields"), PDFArray);
    const signatureWidget = updatedFields.lookup(
      updatedFields.size() - 1,
      PDFDict,
    );
    signatureWidget.set(PDFName.of("T"), PDFString.of(signatureName));
    const prepared = Buffer.from(
      await document.save({ useObjectStreams: false }),
    );
    const reference = signatureWidget.get(PDFName.of("V"));
    if (!(reference instanceof PDFRef))
      throw new Error("Missing signature object");
    const object = document.context.lookup(reference);
    if (!object) throw new Error("Missing signature object body");
    const body = Buffer.alloc(object.sizeInBytes());
    object.copyBytesInto(body, 0);
    // Match the complete generated object, including its reference, not arbitrary
    // /ByteRange text elsewhere in an input string or stream.
    const signatureObject = Buffer.concat([
      Buffer.from(
        `${reference.objectNumber} ${reference.generationNumber} obj\n`,
      ),
      body,
      Buffer.from("\nendobj"),
    ]);
    const offset = prepared.indexOf(signatureObject);
    if (offset < 0 || prepared.indexOf(signatureObject, offset + 1) !== -1) {
      throw new Error("Signature object is not unique");
    }
    // This dictionary was generated above with fixed, empty text metadata.
    const range = /\/ByteRange\s*\[[^\]]+\]/.exec(
      signatureObject.toString("binary"),
    );
    const contents = signatureObject.indexOf("/Contents <");
    if (!range || contents < 0)
      throw new Error("Missing signature placeholder");
    const open = contents + "/Contents ".length;
    const close = signatureObject.indexOf(">", open);
    if (close <= open) throw new Error("Invalid signature placeholder");
    const start = offset + open;
    const end = offset + close + 1;
    const byteRange = `/ByteRange [0 ${start} ${end} ${prepared.length - end}]`;
    if (byteRange.length > range[0].length)
      throw new Error("Byte range is too long");
    prepared.write(
      byteRange.padEnd(range[0].length, " "),
      offset + range.index,
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
    const capacity = close - open - 1;
    const hex = signature.toString("hex");
    if (hex.length > capacity) throw new Error("Signature is too large");
    prepared.write(hex.padEnd(capacity, "0"), start + 1, "ascii");
    return prepared;
  } catch {
    throw new Error(
      "Signing failed. This PDF or certificate is not supported.",
    );
  }
}
