import { createHash } from "node:crypto";
import { pdflibAddPlaceholder } from "@signpdf/placeholder-pdf-lib";
import { P12Signer } from "@signpdf/signer-p12";
import forge from "node-forge";
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
import type { CertificateInfo } from "../shared/contracts";

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

function certificateName(fields: forge.pki.CertificateField[]): string {
  return fields
    .filter((field) => typeof field.value === "string")
    .map(
      (field) =>
        `${field.shortName ?? field.name ?? field.type}=${Number(field.valueTagClass) === forge.asn1.Type.UTF8 ? forge.util.decodeUtf8(String(field.value)) : String(field.value)}`,
    )
    .join(", ");
}

export function inspectCertificate(
  p12: Buffer,
  password: string,
): CertificateInfo {
  checkSize(p12, MAX_P12_BYTES, "Certificate file");
  let container: forge.pkcs12.Pkcs12Pfx;
  try {
    container = forge.pkcs12.pkcs12FromAsn1(
      forge.asn1.fromDer(p12.toString("binary")),
      true,
      password,
    );
  } catch {
    throw new Error(
      "Cannot open the certificate. Check the password and use a supported RSA .p12 or .pfx file.",
    );
  }
  const bags = container.safeContents.flatMap((content) => content.safeBags);
  const keys = bags.filter(
    (bag) =>
      bag.type === forge.pki.oids.pkcs8ShroudedKeyBag ||
      bag.type === forge.pki.oids.keyBag,
  );
  if (keys.length !== 1)
    throw new Error(
      "The certificate file must contain exactly one private key.",
    );
  const keyBag = keys[0];
  const key = keyBag.key;
  if (!key || !("n" in key) || !("e" in key))
    throw new Error("Only RSA private keys are supported.");
  if (keyBag.type !== forge.pki.oids.pkcs8ShroudedKeyBag) {
    throw new Error(
      "This private-key container is unsupported. Export a password-protected .p12 or .pfx file.",
    );
  }
  const matching = bags.flatMap((bag) => {
    const certificate = bag.cert;
    if (!certificate) return [];
    const publicKey = certificate.publicKey;
    return "n" in publicKey &&
      "e" in publicKey &&
      publicKey.n.compareTo(key.n) === 0 &&
      publicKey.e.compareTo(key.e) === 0
      ? [certificate]
      : [];
  });
  if (matching.length !== 1)
    throw new Error("The private key must match exactly one certificate.");
  const certificate = matching[0];
  const now = Date.now();
  if (now < certificate.validity.notBefore.getTime())
    throw new Error("The certificate is not valid yet.");
  if (now > certificate.validity.notAfter.getTime())
    throw new Error("The certificate has expired.");
  const der = forge.asn1
    .toDer(forge.pki.certificateToAsn1(certificate))
    .getBytes();
  return {
    subject: certificateName(certificate.subject.attributes),
    issuer: certificateName(certificate.issuer.attributes),
    validFrom: certificate.validity.notBefore.toISOString(),
    validTo: certificate.validity.notAfter.toISOString(),
    fingerprint: createHash("sha256")
      .update(Buffer.from(der, "binary"))
      .digest("hex"),
  };
}

export async function signPdf(
  pdf: Buffer,
  p12: Buffer,
  password: string,
): Promise<Buffer> {
  const document = await loadUnsignedPdf(pdf);
  inspectCertificate(p12, password);
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
    const signer = new P12Signer(p12, {
      passphrase: password,
      asn1StrictParsing: true,
    });
    const signature = await signer.sign(
      Buffer.concat([prepared.subarray(0, start), prepared.subarray(end)]),
      signingTime,
    );
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
