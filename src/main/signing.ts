import {
  createHash,
  createPrivateKey,
  type KeyObject,
  X509Certificate,
} from "node:crypto";
import {
  beginText,
  clip,
  endPath,
  endText,
  fill,
  moveText,
  PDFArray,
  PDFDict,
  PDFDocument,
  type PDFFont,
  PDFInvalidObject,
  PDFName,
  PDFNumber,
  type PDFObject,
  type PDFPage,
  type PDFRef,
  PDFStream,
  PDFString,
  popGraphicsState,
  pushGraphicsState,
  rectangle,
  StandardFonts,
  setFillingGrayscaleColor,
  setFontAndSize,
  setLineWidth,
  setStrokingGrayscaleColor,
  showText,
  stroke,
} from "@cantoo/pdf-lib";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
  type CertificateInfo,
  MIN_BOX_HEIGHT,
  MIN_BOX_WIDTH,
  type Placement,
} from "../shared/contracts";
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
  let pageCount: number;
  let form: PDFDict | undefined;
  // A PDF can load but still lack a page tree or have a malformed form.
  try {
    document = await PDFDocument.load(bytes, {
      updateMetadata: false,
      throwOnInvalidObject: true,
    });
    pageCount = document.getPageCount();
    form = document.catalog.lookupMaybe(PDFName.of("AcroForm"), PDFDict);
  } catch {
    throw new Error("Cannot read this PDF. Select a valid, unencrypted PDF.");
  }
  if (document.isEncrypted)
    throw new Error("Encrypted PDFs are not supported.");
  if (pageCount === 0)
    throw new Error("The PDF must contain at least one page.");
  // pdf-lib's getForm() deletes XFA data. Reject it before any form access.
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
  const subject = certificateName(certificate.subject);
  const commonName = certificate.subject.typesAndValues
    .map(({ type, value }) => (type === "2.5.4.3" ? value : undefined))
    .filter((value) => value instanceof asn1js.BaseStringBlock)
    .at(-1);
  return {
    info: {
      subject,
      signer: commonName?.getValue() ?? subject,
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

function isFraction(value: unknown): value is number {
  return typeof value === "number" && value >= 0 && value <= 1;
}

// Renderer fractions come from floating-point layout.
const TOLERANCE = 1e-6;

/** Checks the shape of a placement from the renderer. Null means no visible box. */
export function parsePlacement(value: unknown): Placement | null {
  if (value === null || value === undefined) return null;
  const outside = new Error("The signature box must be inside the page.");
  if (typeof value !== "object") throw outside;
  const { page, x, y, width, height } = value as Record<string, unknown>;
  if (
    typeof page !== "number" ||
    !Number.isSafeInteger(page) ||
    page < 0 ||
    !isFraction(x) ||
    !isFraction(y) ||
    !isFraction(width) ||
    !isFraction(height) ||
    x + width > 1 + TOLERANCE ||
    y + height > 1 + TOLERANCE
  ) {
    throw outside;
  }
  return { page, x, y, width, height };
}

/** Appearance matrices that cancel each quarter turn of the page. */
const uprightMatrix: Record<number, number[]> = {
  0: [1, 0, 0, 1, 0, 0],
  90: [0, 1, -1, 0, 0, 0],
  180: [-1, 0, 0, -1, 0, 0],
  270: [0, -1, 1, 0, 0, 0],
};

export interface BoxGeometry {
  /** Widget rectangle in page space: [left, bottom, right, top]. */
  rect: [number, number, number, number];
  /** Box size as displayed, in points. */
  width: number;
  height: number;
  /** Form matrix that keeps the appearance upright on the rotated page. */
  matrix: number[];
}

/**
 * Maps a placement on the displayed page to page space. Like pdf.js, the
 * displayed area is the crop box clipped to the media box, and only quarter
 * turns rotate the page.
 */
export function boxGeometry(
  document: PDFDocument,
  placement: Placement,
): BoxGeometry {
  if (placement.page >= document.getPageCount())
    throw new Error("The signature box must be inside the page.");
  const page = document.getPage(placement.page);
  const edges = ({
    x,
    y,
    width,
    height,
  }: ReturnType<PDFPage["getCropBox"]>) => ({
    left: Math.min(x, x + width),
    bottom: Math.min(y, y + height),
    right: Math.max(x, x + width),
    top: Math.max(y, y + height),
  });
  const media = edges(page.getMediaBox());
  const crop = edges(page.getCropBox());
  let view = {
    left: Math.max(media.left, crop.left),
    bottom: Math.max(media.bottom, crop.bottom),
    right: Math.min(media.right, crop.right),
    top: Math.min(media.top, crop.top),
  };
  if (view.right <= view.left || view.top <= view.bottom) view = media;
  const angle = page.getRotation().angle;
  const rotation = angle % 90 === 0 ? ((angle % 360) + 360) % 360 : 0;
  const pageWidth = view.right - view.left;
  const pageHeight = view.top - view.bottom;
  const [shownWidth, shownHeight] =
    rotation % 180 === 0 ? [pageWidth, pageHeight] : [pageHeight, pageWidth];
  const width = Math.min(placement.width, 1 - placement.x) * shownWidth;
  const height = Math.min(placement.height, 1 - placement.y) * shownHeight;
  if (
    width < MIN_BOX_WIDTH - TOLERANCE ||
    height < MIN_BOX_HEIGHT - TOLERANCE
  ) {
    throw new Error(
      `The signature box must be at least ${MIN_BOX_WIDTH} by ${MIN_BOX_HEIGHT} points.`,
    );
  }
  // (across, down) on the displayed page to page space.
  const toPage = (across: number, down: number): [number, number] => {
    switch (rotation) {
      case 90:
        return [view.left + down, view.bottom + across];
      case 180:
        return [view.right - across, view.bottom + down];
      case 270:
        return [view.right - down, view.top - across];
      default:
        return [view.left + across, view.top - down];
    }
  };
  const left = placement.x * shownWidth;
  const top = placement.y * shownHeight;
  const [x1, y1] = toPage(left, top);
  const [x2, y2] = toPage(left + width, top + height);
  return {
    rect: [
      Math.min(x1, x2),
      Math.min(y1, y2),
      Math.max(x1, x2),
      Math.max(y1, y2),
    ],
    width,
    height,
    matrix: uprightMatrix[rotation],
  };
}

/** Text in the visible box. It names the signer; it does not claim validity. */
export function boxText(signer: string, time: Date): string[] {
  const minute = time.toISOString().slice(0, 16).replace("T", " ");
  return ["Digitally signed by", signer, `Date: ${minute} UTC`];
}

function drawBox(
  document: PDFDocument,
  font: PDFFont,
  box: BoxGeometry,
  lines: string[],
): PDFRef {
  const { width, height } = box;
  const supported = new Set(font.getCharacterSet());
  // Helvetica covers Latin-1 names; other characters cannot be encoded.
  const encodable = lines.map((line) =>
    [...line]
      .map((character) =>
        supported.has(character.codePointAt(0) ?? 0) ? character : "?",
      )
      .join(""),
  );
  const bar = Math.min(6, Math.max(2, width * 0.03));
  const padding = Math.min(6, height * 0.12);
  const textLeft = bar + padding;
  const widest = Math.max(
    ...encodable.map((line) => font.widthOfTextAtSize(line, 1)),
  );
  const leading = 1.2;
  const size = Math.min(
    12,
    (height - 2 * padding) / (encodable.length * leading),
    (width - textLeft - padding) / widest,
  );
  const blockTop = (height + encodable.length * leading * size) / 2;
  const operators = [
    pushGraphicsState(),
    rectangle(0, 0, width, height),
    clip(),
    endPath(),
    // Opaque, so page content under the box does not hide the text.
    setFillingGrayscaleColor(1),
    rectangle(0, 0, width, height),
    fill(),
    setLineWidth(0.75),
    setStrokingGrayscaleColor(0.55),
    rectangle(0.375, 0.375, width - 0.75, height - 0.75),
    stroke(),
    setFillingGrayscaleColor(0.15),
    // The bar marks the left edge, so readers show which way is up.
    rectangle(0, 0, bar, height),
    fill(),
    beginText(),
    setFontAndSize("F1", size),
    moveText(textLeft, blockTop - size),
    ...encodable.flatMap((line, index) => [
      ...(index > 0 ? [moveText(0, -leading * size)] : []),
      showText(font.encodeText(line)),
    ]),
    endText(),
    popGraphicsState(),
  ];
  return document.context.register(
    document.context.formXObject(operators, {
      BBox: [0, 0, width, height],
      Matrix: box.matrix,
      Resources: { Font: { F1: font.ref } },
    }),
  );
}

interface WidgetOptions {
  box: BoxGeometry | null;
  pageIndex: number;
  signer: string;
  time: Date;
  /** The signature dictionary. A preview has none. */
  value?: PDFRef;
}

async function addSignatureWidget(
  document: PDFDocument,
  options: WidgetOptions,
): Promise<void> {
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
  const { context } = document;
  const { box } = options;
  const page = document.getPage(options.pageIndex);
  const appearance = box
    ? drawBox(
        document,
        await document.embedFont(StandardFonts.Helvetica),
        box,
        boxText(options.signer, options.time),
      )
    : // An empty appearance stream, required for PDF/A.
      context.register(
        context.formXObject([], { BBox: [0, 0, 0, 0], Resources: {} }),
      );
  const widget = context.register(
    context.obj({
      Type: "Annot",
      Subtype: "Widget",
      FT: "Sig",
      Rect: box?.rect ?? [0, 0, 0, 0],
      ...(options.value ? { V: options.value } : {}),
      T: PDFString.of(signatureName),
      F: 4, // Print
      P: page.ref,
      AP: { N: appearance },
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
  form.set(PDFName.of("SigFlags"), PDFNumber.of((flags?.asNumber() ?? 0) | 3));
}

/** An unsigned copy with the visible box, for the final preview. */
export async function previewBox(
  pdf: Buffer,
  placement: Placement,
  signer: string,
): Promise<Buffer> {
  const document = await loadUnsignedPdf(pdf);
  const box = boxGeometry(document, placement);
  try {
    await addSignatureWidget(document, {
      box,
      pageIndex: placement.page,
      signer,
      time: new Date(),
    });
    return Buffer.from(await document.save({ useObjectStreams: false }));
  } catch {
    throw new Error("Cannot draw the signature box on this PDF.");
  }
}

export async function signPdf(
  pdf: Buffer,
  p12: Buffer,
  password: string,
  placement: Placement | null = null,
): Promise<Buffer> {
  const document = await loadUnsignedPdf(pdf);
  const box = placement && boxGeometry(document, placement);
  const certificate = readCertificate(p12, password);
  try {
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
    const signatureRef = document.context.register(
      PDFInvalidObject.of(Buffer.from(signatureBody, "latin1")),
    );
    await addSignatureWidget(document, {
      box,
      pageIndex: placement?.page ?? 0,
      signer: certificate.info.signer,
      time: signingTime,
      value: signatureRef,
    });
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
