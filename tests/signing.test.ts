import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFName,
  PDFNumber,
  PDFString,
} from "@cantoo/pdf-lib";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  inspectPdf,
  MAX_P12_BYTES,
  MAX_PDF_BYTES,
  openPkcs12,
  signPdf,
} from "../src/main/signing";

const password = "disposable-test-password";
const fixtures = mkdtempSync(join(tmpdir(), "garabato-certificate-test-"));
let fixtureCount = 0;

afterAll(() => rmSync(fixtures, { recursive: true, force: true }));

function fixturePath(extension: string): string {
  fixtureCount += 1;
  return join(fixtures, `fixture-${fixtureCount}.${extension}`);
}

function openssl(args: string[]): Buffer {
  const result = spawnSync("openssl", args);
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.toString());
  return result.stdout;
}

function keyFile(type: "rsa" | "ec" = "rsa"): string {
  const pair =
    type === "rsa"
      ? generateKeyPairSync("rsa", { modulusLength: 2048 })
      : generateKeyPairSync("ec", { namedCurve: "P-256" });
  const path = fixturePath("key.pem");
  writeFileSync(
    path,
    pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    { mode: 0o600 },
  );
  return path;
}

const rsaKey = keyFile();
const otherRsaKey = keyFile();

function opensslTime(date: Date): string {
  return `${date.toISOString().replace(/[-:T]/g, "").slice(0, 14)}Z`;
}

function certificatePem(
  options: { key?: string; subject?: string; from?: Date; to?: Date } = {},
): string {
  const path = fixturePath("cert.pem");
  openssl([
    "req",
    "-x509",
    "-new",
    "-key",
    options.key ?? rsaKey,
    "-utf8",
    "-subj",
    options.subject ?? "/CN=Disposable test certificate",
    "-not_before",
    opensslTime(options.from ?? new Date(Date.now() - 60_000)),
    "-not_after",
    opensslTime(options.to ?? new Date(Date.now() + 86_400_000)),
    "-out",
    path,
  ]);
  return path;
}

/** Exports a PKCS#12 file with OpenSSL. Extra arguments select its algorithms. */
function certificateFile(
  options: {
    key?: string;
    subject?: string;
    from?: Date;
    to?: Date;
    password?: string;
    args?: string[];
  } = {},
): Buffer {
  const key = options.key ?? rsaKey;
  const path = fixturePath("p12");
  openssl([
    "pkcs12",
    "-export",
    "-inkey",
    key,
    "-in",
    certificatePem({ ...options, key }),
    "-passout",
    `pass:${options.password ?? password}`,
    "-out",
    path,
    ...(options.args ?? []),
  ]);
  return readFileSync(path);
}

// OpenSSL refuses to export unusual containers, so these build bags directly.
function shroudedKeyBag(key: string): pkijs.SafeBag {
  const der = openssl([
    ...["pkcs8", "-topk8", "-in", key, "-v2", "aes-256-cbc"],
    ...["-passout", `pass:${password}`, "-outform", "DER"],
  ]);
  return new pkijs.SafeBag({
    bagId: "1.2.840.113549.1.12.10.1.2",
    bagValue: pkijs.PKCS8ShroudedKeyBag.fromBER(new Uint8Array(der)),
  });
}

function plainKeyBag(key: string): pkijs.SafeBag {
  const der = openssl([
    "pkcs8",
    "-topk8",
    "-in",
    key,
    "-nocrypt",
    "-outform",
    "DER",
  ]);
  return new pkijs.SafeBag({
    bagId: "1.2.840.113549.1.12.10.1.1",
    bagValue: pkijs.PrivateKeyInfo.fromBER(new Uint8Array(der)),
  });
}

function certificateBag(key = rsaKey): pkijs.SafeBag {
  const der = openssl([
    "x509",
    "-in",
    certificatePem({ key }),
    "-outform",
    "DER",
  ]);
  return new pkijs.SafeBag({
    bagId: "1.2.840.113549.1.12.10.1.3",
    bagValue: new pkijs.CertBag({
      certId: "1.2.840.113549.1.9.22.1",
      certValue: new asn1js.OctetString({ valueHex: new Uint8Array(der) }),
    }),
  });
}

/** Builds an unencrypted PKCS#12 file without a MAC. */
function containerFile(safeBags: pkijs.SafeBag[]): Buffer {
  const data = (value: { toSchema(): asn1js.AsnType }) =>
    new pkijs.ContentInfo({
      contentType: "1.2.840.113549.1.7.1",
      content: new asn1js.OctetString({
        valueHex: value.toSchema().toBER(),
      }),
    });
  const authSafe = new pkijs.AuthenticatedSafe({
    safeContents: [data(new pkijs.SafeContents({ safeBags }))],
  });
  return Buffer.from(
    new pkijs.PFX({ version: 3, authSafe: data(authSafe) }).toSchema().toBER(),
  );
}

// OpenSSL verifies both the detached content digest and the CMS signature.
// -noverify intentionally disables trust-chain checks for our disposable certificate.
function verifyWithOpenSsl(signed: Buffer): {
  valid: boolean;
  verifiedContent: Buffer;
  error: string;
} {
  const range = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(
    signed.toString("binary"),
  );
  if (!range) throw new Error("Missing PDF ByteRange");
  const [start, length, secondStart, secondLength] = range
    .slice(1)
    .map(Number) as [number, number, number, number];
  expect(start).toBe(0);
  expect(secondStart + secondLength).toBe(signed.length);
  const content = Buffer.concat([
    signed.subarray(start, start + length),
    signed.subarray(secondStart, secondStart + secondLength),
  ]);
  const hex = signed.subarray(length + 1, secondStart - 1).toString("ascii");
  const paddedCms = Buffer.from(hex, "hex");
  const lengthByte = paddedCms[1];
  const lengthOctets = lengthByte & 0x7f;
  const cmsLength =
    lengthByte < 128
      ? 2 + lengthByte
      : 2 + lengthOctets + paddedCms.readUIntBE(2, lengthOctets);
  const folder = mkdtempSync(join(tmpdir(), "garabato-signature-test-"));
  try {
    writeFileSync(
      join(folder, "signature.der"),
      paddedCms.subarray(0, cmsLength),
    );
    writeFileSync(join(folder, "content.bin"), content);
    const verification = spawnSync("openssl", [
      "cms",
      "-verify",
      "-binary",
      "-inform",
      "DER",
      "-in",
      join(folder, "signature.der"),
      "-content",
      join(folder, "content.bin"),
      "-noverify",
      "-out",
      join(folder, "verified.bin"),
    ]);
    if (verification.error) throw verification.error;
    return {
      valid: verification.status === 0,
      error: verification.stderr.toString(),
      verifiedContent: readFileSync(join(folder, "verified.bin")),
    };
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
}

describe("local PDF signing", () => {
  let pdf: Buffer;
  let p12: Buffer;
  let signed: Buffer;

  beforeAll(async () => {
    const document = await PDFDocument.create();
    document.addPage().drawText("Disposable signing fixture");
    pdf = Buffer.from(await document.save());
    p12 = certificateFile();
    signed = await signPdf(pdf, openPkcs12(p12, password));
  });

  it("inspects a PDF and the matching RSA certificate", async () => {
    expect(await inspectPdf(pdf)).toEqual({ pageCount: 1 });
    expect(openPkcs12(p12, password).info).toMatchObject({
      subject: "CN=Disposable test certificate",
      issuer: "CN=Disposable test certificate",
      fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
  });

  it("creates a readable PDF with an independently verified detached CMS signature", async () => {
    expect((await PDFDocument.load(signed)).getPageCount()).toBe(1);
    const verified = verifyWithOpenSsl(signed);
    expect(verified.valid).toBe(true);
    expect(verified.verifiedContent.subarray(0, 5).toString()).toBe("%PDF-");
  });

  it("fails independent verification when signed bytes change", () => {
    const changed = Buffer.from(signed);
    changed[7] = changed[7] === 55 ? 54 : 55;
    expect(verifyWithOpenSsl(changed).valid).toBe(false);
  });

  it("preserves form fields and flags stored as indirect objects", async () => {
    const document = await PDFDocument.create();
    const page = document.addPage();
    const field = document.getForm().createTextField("Applicant");
    field.setText("Example applicant");
    field.addToPage(page);
    const form = document.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
    const fields = form.lookup(PDFName.of("Fields"), PDFArray);
    form.set(PDFName.of("Fields"), document.context.register(fields));
    form.set(
      PDFName.of("SigFlags"),
      document.context.register(PDFNumber.of(0)),
    );
    const result = await signPdf(
      Buffer.from(await document.save()),
      openPkcs12(p12, password),
    );
    const output = await PDFDocument.load(result, {
      throwOnInvalidObject: true,
    });
    expect(output.getForm().getTextField("Applicant").getText()).toBe(
      "Example applicant",
    );
    const verification = verifyWithOpenSsl(result);
    expect(verification.valid, verification.error).toBe(true);
  });

  it("keeps PDF syntax valid for Unicode, parentheses, and backslashes in certificate subjects", async () => {
    const certificate = certificateFile({ subject: "/CN=María (Equipo\\\\" });
    expect(openPkcs12(certificate, password).info.subject).toBe(
      "CN=María (Equipo\\",
    );
    const result = await signPdf(pdf, openPkcs12(certificate, password));
    const output = await PDFDocument.load(result, {
      throwOnInvalidObject: true,
    });
    expect(output.getPageCount()).toBe(1);
    const verification = verifyWithOpenSsl(result);
    expect(verification.valid, verification.error).toBe(true);
  });

  it("gives the signature a unique field name without changing existing fields", async () => {
    const document = await PDFDocument.create();
    const page = document.addPage();
    for (const name of [
      "Signature1",
      "GarabatoSignature",
      "GarabatoSignature2",
      "GarabatoSignature3.Child",
    ]) {
      const field = document.getForm().createTextField(name);
      field.setText(name);
      field.addToPage(page);
    }
    const result = await signPdf(
      Buffer.from(await document.save()),
      openPkcs12(p12, password),
    );
    const output = await PDFDocument.load(result);
    const form = output.getForm();
    const names = form.getFields().map((field) => field.getName());
    expect(new Set(names).size).toBe(names.length);
    expect(form.getSignature("GarabatoSignature4")).toBeTruthy();
    expect(form.getTextField("GarabatoSignature3.Child").getText()).toBe(
      "GarabatoSignature3.Child",
    );
    expect(form.getTextField("Signature1").getText()).toBe("Signature1");
    const verification = verifyWithOpenSsl(result);
    expect(verification.valid, verification.error).toBe(true);
  });

  it("preserves a multi-valued Unicode issuer RDN in the CMS signer identifier", async () => {
    const certificate = certificateFile({ subject: "/CN=Issuér+OU=Signing" });
    expect(openPkcs12(certificate, password).info.issuer).toContain("Issuér");
    const result = await signPdf(pdf, openPkcs12(certificate, password));
    const verification = verifyWithOpenSsl(result);
    expect(verification.valid, verification.error).toBe(true);
  });

  it("rejects an existing signature before rewriting the PDF", async () => {
    await expect(inspectPdf(signed)).rejects.toThrow(
      "already contains a signature",
    );
    await expect(signPdf(signed, openPkcs12(p12, password))).rejects.toThrow(
      "already contains a signature",
    );
  });

  it("rejects XFA forms before the PDF library can remove their content", async () => {
    const document = await PDFDocument.create();
    document.addPage();
    const xfa = document.context.register(
      document.context.stream("<xfa>Form content</xfa>"),
    );
    const form = document.context.register(
      document.context.obj({ Fields: [], XFA: xfa }),
    );
    document.catalog.set(PDFName.of("AcroForm"), form);
    const input = Buffer.from(await document.save());
    await expect(inspectPdf(input)).rejects.toThrow(
      "XFA forms are not supported",
    );
    await expect(signPdf(input, openPkcs12(p12, password))).rejects.toThrow(
      "XFA forms are not supported",
    );
  });

  it("does not mistake literal ByteRange text in another object for the signature placeholder", async () => {
    const document = await PDFDocument.create();
    document.addPage();
    document.getForm();
    const note = "Ordinary /ByteRange text in the last original object";
    document.catalog.set(
      PDFName.of("Note"),
      document.context.register(PDFString.of(note)),
    );
    const input = Buffer.from(await document.save({ useObjectStreams: false }));
    const result = await signPdf(input, openPkcs12(p12, password));
    const output = await PDFDocument.load(result, {
      throwOnInvalidObject: true,
    });
    expect(
      output.catalog.lookup(PDFName.of("Note"), PDFString).decodeText(),
    ).toBe(note);
    expect(output.getForm().getSignature("GarabatoSignature")).toBeTruthy();
    const verification = verifyWithOpenSsl(result);
    expect(verification.valid, verification.error).toBe(true);
  });

  it("rejects wrong passwords without including the supplied password", async () => {
    expect(() => openPkcs12(p12, "wrong-secret")).toThrow("Check the password");
    expect(() => openPkcs12(p12, "wrong-secret")).not.toThrow("wrong-secret");
  });

  it("rejects expired and not-yet-valid certificates", () => {
    expect(() =>
      openPkcs12(
        certificateFile({ to: new Date(Date.now() - 1000) }),
        password,
      ),
    ).toThrow("expired");
    expect(() =>
      openPkcs12(
        certificateFile({ from: new Date(Date.now() + 60_000) }),
        password,
      ),
    ).toThrow("not valid yet");
  });

  it("rejects missing keys and certificates that do not match the private key", () => {
    expect(() =>
      openPkcs12(containerFile([certificateBag()]), password),
    ).toThrow("exactly one private key");
    expect(() =>
      openPkcs12(
        containerFile([shroudedKeyBag(otherRsaKey), certificateBag()]),
        password,
      ),
    ).toThrow("must match exactly one certificate");
  });

  it("rejects containers with multiple private keys", () => {
    expect(() =>
      openPkcs12(
        containerFile([
          shroudedKeyBag(rsaKey),
          shroudedKeyBag(rsaKey),
          certificateBag(),
        ]),
        password,
      ),
    ).toThrow("exactly one private key");
  });

  it("rejects unencrypted private keys and non-RSA keys", () => {
    expect(() =>
      openPkcs12(
        containerFile([plainKeyBag(rsaKey), certificateBag()]),
        password,
      ),
    ).toThrow("password-protected");
    expect(() =>
      openPkcs12(certificateFile({ key: keyFile("ec") }), password),
    ).toThrow("Only RSA");
  });

  it.each([
    ["AES-256 with a SHA-256 MAC (OpenSSL 3 default)", []],
    ["legacy RC2-40 certificates and 3DES keys", ["-legacy"]],
    [
      "3DES certificates and keys with a SHA-1 MAC",
      [
        "-certpbe",
        "PBE-SHA1-3DES",
        "-keypbe",
        "PBE-SHA1-3DES",
        "-macalg",
        "sha1",
      ],
    ],
    ["unencrypted certificates", ["-certpbe", "NONE"]],
  ])("signs with a PKCS#12 file using %s", async (_name, args) => {
    // A non-ASCII password exercises both the BMPString and UTF-8 encodings.
    const unicodePassword = "contraseña-ñ-€";
    const certificate = certificateFile({ password: unicodePassword, args });
    expect(openPkcs12(certificate, unicodePassword).info.subject).toBe(
      "CN=Disposable test certificate",
    );
    expect(() => openPkcs12(certificate, password)).toThrow(
      "Check the password",
    );
    const verification = verifyWithOpenSsl(
      await signPdf(pdf, openPkcs12(certificate, unicodePassword)),
    );
    expect(verification.valid, verification.error).toBe(true);
  });

  it("rejects excessive key-derivation iteration counts", () => {
    expect(() =>
      openPkcs12(certificateFile({ args: ["-iter", "1000001"] }), password),
    ).toThrow("Cannot open");
  });

  it("rejects malformed inputs and oversized inputs", async () => {
    await expect(inspectPdf(Buffer.from("not a pdf"))).rejects.toThrow(
      "valid, unencrypted PDF",
    );
    // pdf-lib loads this, but it has no catalog or page tree.
    await expect(inspectPdf(Buffer.from("%PDF-1.7\n%%EOF\n"))).rejects.toThrow(
      "valid, unencrypted PDF",
    );
    await expect(inspectPdf(Buffer.alloc(MAX_PDF_BYTES + 1))).rejects.toThrow(
      "25 MiB",
    );
    expect(() => openPkcs12(Buffer.from("not a p12"), password)).toThrow(
      "Cannot open",
    );
    expect(() => openPkcs12(Buffer.alloc(MAX_P12_BYTES + 1), password)).toThrow(
      "2 MiB",
    );
  });

  it("rejects encrypted PDFs", async () => {
    const document = await PDFDocument.create();
    document.addPage();
    document.context.trailerInfo.Encrypt = document.context.register(
      document.context.obj({ Filter: PDFName.of("Standard") }),
    );
    await expect(
      inspectPdf(Buffer.from(await document.save())),
    ).rejects.toThrow("unencrypted PDF");
  });
});
