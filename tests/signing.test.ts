import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import forge from "node-forge";
import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFName,
  PDFNumber,
  PDFString,
} from "pdf-lib";
import { beforeAll, describe, expect, it } from "vitest";
import {
  inspectCertificate,
  inspectPdf,
  MAX_P12_BYTES,
  MAX_PDF_BYTES,
  signPdf,
} from "../src/main/signing";

const password = "disposable-test-password";
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKey = forge.pki.privateKeyFromPem(
  pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
);
const publicKey = forge.pki.publicKeyFromPem(
  pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
);

function certificateFile(
  options: {
    from?: Date;
    to?: Date;
    includeKey?: boolean;
    mismatch?: boolean;
    duplicateKey?: boolean;
    subject?: string;
  } = {},
): Buffer {
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = options.mismatch
    ? forge.pki.rsa.generateKeyPair(2048).publicKey
    : publicKey;
  certificate.serialNumber = "01";
  certificate.validity.notBefore =
    options.from ?? new Date(Date.now() - 60_000);
  certificate.validity.notAfter =
    options.to ?? new Date(Date.now() + 86_400_000);
  certificate.setSubject([
    {
      name: "commonName",
      value: options.subject ?? "Disposable test certificate",
      // Forge expects the ASN.1 tag type here; @types/node-forge calls it Class.
      valueTagClass: forge.asn1.Type.UTF8 as number as forge.asn1.Class,
    },
  ]);
  certificate.setIssuer(certificate.subject.attributes);
  certificate.sign(privateKey, forge.md.sha256.create());
  const p12 = forge.pkcs12.toPkcs12Asn1(
    options.includeKey === false ? null : privateKey,
    certificate,
    password,
    {
      algorithm: "aes256",
      count: 2048,
      useMac: !options.duplicateKey,
    },
  );
  if (options.duplicateKey) duplicateKeyBag(p12);
  return Buffer.from(forge.asn1.toDer(p12).getBytes(), "binary");
}

function duplicateKeyBag(node: forge.asn1.Asn1): void {
  if (Array.isArray(node.value)) {
    for (const child of [...node.value]) {
      if (typeof child === "string") continue;
      const first = Array.isArray(child.value) ? child.value[0] : undefined;
      if (
        first &&
        typeof first !== "string" &&
        first.type === forge.asn1.Type.OID &&
        typeof first.value === "string" &&
        forge.asn1.derToOid(first.value) === forge.pki.oids.pkcs8ShroudedKeyBag
      ) {
        node.value.push(child);
        return;
      }
      duplicateKeyBag(child);
    }
  } else if (
    node.type === forge.asn1.Type.OCTETSTRING &&
    typeof node.value === "string"
  ) {
    let nested: forge.asn1.Asn1;
    try {
      nested = forge.asn1.fromDer(node.value);
    } catch {
      return;
    }
    duplicateKeyBag(nested);
    node.value = forge.asn1.toDer(nested).getBytes();
  }
}

function multiValuedIssuerFile(): Buffer {
  const folder = mkdtempSync(join(tmpdir(), "garabato-issuer-test-"));
  try {
    const keyPath = join(folder, "key.pem");
    const certPath = join(folder, "cert.pem");
    const p12Path = join(folder, "cert.p12");
    writeFileSync(keyPath, forge.pki.privateKeyToPem(privateKey), {
      mode: 0o600,
    });
    for (const args of [
      [
        "req",
        "-new",
        "-x509",
        "-key",
        keyPath,
        "-out",
        certPath,
        "-days",
        "1",
        "-utf8",
        "-subj",
        "/CN=Issuér+OU=Signing",
      ],
      [
        "pkcs12",
        "-export",
        "-inkey",
        keyPath,
        "-in",
        certPath,
        "-out",
        p12Path,
        "-passout",
        `pass:${password}`,
      ],
    ]) {
      const result = spawnSync("openssl", args);
      if (result.error) throw result.error;
      if (result.status !== 0) throw new Error(result.stderr.toString());
    }
    return readFileSync(p12Path);
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
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
    signed = await signPdf(pdf, p12, password);
  });

  it("inspects a PDF and the matching RSA certificate", async () => {
    expect(await inspectPdf(pdf)).toEqual({ pageCount: 1 });
    expect(inspectCertificate(p12, password)).toMatchObject({
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
      p12,
      password,
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
    const certificate = certificateFile({ subject: "María (Equipo\\" });
    expect(inspectCertificate(certificate, password).subject).toBe(
      "CN=María (Equipo\\",
    );
    const result = await signPdf(pdf, certificate, password);
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
      p12,
      password,
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
    const certificate = multiValuedIssuerFile();
    expect(inspectCertificate(certificate, password).issuer).toContain(
      "Issuér",
    );
    const result = await signPdf(pdf, certificate, password);
    const verification = verifyWithOpenSsl(result);
    expect(verification.valid, verification.error).toBe(true);
  });

  it("rejects an existing signature before rewriting the PDF", async () => {
    await expect(inspectPdf(signed)).rejects.toThrow(
      "already contains a signature",
    );
    await expect(signPdf(signed, p12, password)).rejects.toThrow(
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
    await expect(signPdf(input, p12, password)).rejects.toThrow(
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
    const result = await signPdf(input, p12, password);
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
    expect(() => inspectCertificate(p12, "wrong-secret")).toThrow(
      "Check the password",
    );
    await expect(signPdf(pdf, p12, "wrong-secret")).rejects.not.toThrow(
      "wrong-secret",
    );
  });

  it("rejects expired and not-yet-valid certificates", () => {
    expect(() =>
      inspectCertificate(
        certificateFile({ to: new Date(Date.now() - 1000) }),
        password,
      ),
    ).toThrow("expired");
    expect(() =>
      inspectCertificate(
        certificateFile({ from: new Date(Date.now() + 60_000) }),
        password,
      ),
    ).toThrow("not valid yet");
  });

  it("rejects missing keys and certificates that do not match the private key", () => {
    expect(() =>
      inspectCertificate(certificateFile({ includeKey: false }), password),
    ).toThrow("exactly one private key");
    expect(() =>
      inspectCertificate(certificateFile({ mismatch: true }), password),
    ).toThrow("must match exactly one certificate");
  });

  it("rejects containers with multiple private keys", () => {
    expect(() =>
      inspectCertificate(certificateFile({ duplicateKey: true }), password),
    ).toThrow("exactly one private key");
  });

  it("rejects malformed inputs and oversized inputs", async () => {
    await expect(inspectPdf(Buffer.from("not a pdf"))).rejects.toThrow(
      "valid, unencrypted PDF",
    );
    await expect(inspectPdf(Buffer.alloc(MAX_PDF_BYTES + 1))).rejects.toThrow(
      "25 MiB",
    );
    expect(() =>
      inspectCertificate(Buffer.from("not a p12"), password),
    ).toThrow("Cannot open");
    expect(() =>
      inspectCertificate(Buffer.alloc(MAX_P12_BYTES + 1), password),
    ).toThrow("2 MiB");
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
