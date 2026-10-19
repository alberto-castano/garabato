import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PDFDocument } from "@cantoo/pdf-lib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { inspectPdf, openPkcs12, signPdf } from "../src/main/signing";
import { type FnmtIdentity, fnmtIdentity } from "./support/fnmt";

// Independent validators. Versions are pinned here and recorded in
// docs/interoperability.md. Install with `brew install poppler uv`.
const PYHANKO = ["--from", "pyhanko-cli==0.5.0", "--with", "pyhanko==0.37.0"];

const password = "contraseña-ñ-€";
const folder = mkdtempSync(join(tmpdir(), "garabato-interop-test-"));
let fileCount = 0;

afterAll(() => rmSync(folder, { recursive: true, force: true }));

function run(command: string, args: string[]) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.error) throw result.error;
  return { code: result.status, output: result.stdout + result.stderr };
}

function writePdf(bytes: Buffer | Uint8Array): string {
  fileCount += 1;
  const path = join(folder, `document-${fileCount}.pdf`);
  writeFileSync(path, bytes);
  return path;
}

/** Creates an NSS database for pdfsig; trusts root when given. */
function nssDatabase(name: string, root?: string): string {
  const path = join(folder, name);
  mkdirSync(path);
  const database = `sql:${path}`;
  const created = run("certutil", ["-N", "-d", database, "--empty-password"]);
  expect(created.code, created.output).toBe(0);
  if (root) {
    const added = run("certutil", [
      ...["-A", "-d", database, "-n", "Disposable root"],
      ...["-t", "C,C,C", "-i", root],
    ]);
    expect(added.code, added.output).toBe(0);
  }
  return database;
}

/** Poppler pdfsig: signature integrity and, against database, certificate trust. */
function pdfsig(path: string, database: string): string {
  return run("pdfsig", ["-nssdir", database, path]).output;
}

/** pyHanko: integrity, trust path to root, and changes after signing. */
function pyhanko(path: string, root: string): string {
  return run("uvx", [
    ...PYHANKO,
    ...["pyhanko", "sign", "validate", "--executive-summary"],
    ...["--trust", root, "--trust-replace", "--no-revocation-check", path],
  ]).output;
}

async function simplePdf(): Promise<Buffer> {
  const document = await PDFDocument.create();
  document.addPage().drawText("Disposable interoperability fixture");
  return Buffer.from(await document.save());
}

describe("independent PDF reader interoperability", () => {
  let identity: FnmtIdentity;
  let untrusted: string;
  let trusted: string;

  beforeAll(() => {
    identity = fnmtIdentity(join(folder, "identity"), {
      givenName: "MARÍA JOSÉ",
      surnames: "MUÑOZ GARCÍA-PELÁEZ",
      password,
    });
    // An empty database separates mathematical validity from trust.
    untrusted = nssDatabase("nss-untrusted");
    trusted = nssDatabase("nss-trusted", identity.root);
  }, 60_000);

  it("validates an FNMT-like Unicode identity in pdfsig and pyHanko", async () => {
    expect(openPkcs12(identity.p12, password).info).toMatchObject({
      subject:
        "C=ES, serialNumber=IDCES-99999999R, GN=MARÍA JOSÉ, SN=MUÑOZ GARCÍA-PELÁEZ, CN=MUÑOZ GARCÍA-PELÁEZ MARÍA JOSÉ - 99999999R",
      issuer: "C=ES, O=FNMT-RCM PRUEBAS, OU=Ceres, CN=AC FNMT Usuarios PRUEBAS",
    });
    const path = writePdf(
      await signPdf(await simplePdf(), openPkcs12(identity.p12, password)),
    );

    const withoutTrust = pdfsig(path, untrusted);
    expect(withoutTrust).toContain(
      `Signer Certificate Common Name: ${identity.subjectCommonName}`,
    );
    expect(withoutTrust).toContain("Signing Hash Algorithm: SHA-256");
    expect(withoutTrust).toContain("Signature Type: adbe.pkcs7.detached");
    expect(withoutTrust).toContain("Total document signed");
    expect(withoutTrust).toContain("Signature Validation: Signature is Valid.");
    expect(withoutTrust).toContain(
      "Certificate Validation: Certificate issuer isn't Trusted.",
    );
    expect(pdfsig(path, trusted)).toContain(
      "Certificate Validation: Certificate is Trusted.",
    );
    expect(pyhanko(path, identity.root)).toMatch(/:VALID$/m);
  });

  it("validates a signed AcroForm and keeps its field value", async () => {
    const document = await PDFDocument.create();
    const field = document.getForm().createTextField("Solicitante");
    field.setText("Muñoz García-Peláez, María José");
    field.addToPage(document.addPage());
    const signed = await signPdf(
      Buffer.from(await document.save()),
      openPkcs12(identity.p12, password),
    );
    const output = await PDFDocument.load(signed);
    expect(output.getForm().getTextField("Solicitante").getText()).toBe(
      "Muñoz García-Peláez, María José",
    );
    const path = writePdf(signed);
    expect(pdfsig(path, trusted)).toContain("Signature is Valid.");
    expect(pyhanko(path, identity.root)).toMatch(/:VALID$/m);
  });

  it("reports changed signed bytes as invalid", async () => {
    const signed = await signPdf(
      await simplePdf(),
      openPkcs12(identity.p12, password),
    );
    // The header comment is inside the first signed range.
    signed[7] = signed[7] === 55 ? 54 : 55;
    const path = writePdf(signed);
    expect(pdfsig(path, trusted)).toContain(
      "Signature Validation: Digest Mismatch.",
    );
    expect(pyhanko(path, identity.root)).toMatch(/:INVALID$/m);
  });

  it("reports page changes appended after signing", async () => {
    const signed = await signPdf(
      await simplePdf(),
      openPkcs12(identity.p12, password),
    );
    const document = await PDFDocument.load(signed, {
      forIncrementalUpdate: true,
    });
    document.getPage(0).drawText("Added after signing", { y: 100 });
    // Match the signed revision's xref table. Mixing in an xref stream makes
    // Acrobat reject the byte range instead of reporting the change.
    const path = writePdf(await document.commit({ useObjectStreams: false }));
    // The original revision is still intact, but it no longer covers the file.
    const result = pdfsig(path, trusted);
    expect(result).toContain("Signature is Valid.");
    expect(result).not.toContain("Total document signed");
    expect(pyhanko(path, identity.root)).toMatch(/:INVALID$/m);
  });

  it("signs with an expired CA: mathematically valid, but not trusted", async () => {
    // Garabato checks only the signer's dates. It does not validate the chain.
    const expiredCa = fnmtIdentity(join(folder, "expired-ca"), {
      givenName: "JUAN",
      surnames: "ESPAÑOL ESPAÑOL",
      password,
      intermediate: {
        from: new Date(Date.now() - 30 * 86_400_000),
        to: new Date(Date.now() - 86_400_000),
      },
    });
    const path = writePdf(
      await signPdf(await simplePdf(), openPkcs12(expiredCa.p12, password)),
    );
    expect(pdfsig(path, untrusted)).toContain(
      "Signature Validation: Signature is Valid.",
    );
    expect(pyhanko(path, expiredCa.root)).toMatch(/:INVALID$/m);
  }, 60_000);

  it("rejects a wrong password and invalid signer dates in a chained identity", () => {
    expect(() => openPkcs12(identity.p12, "contraseña-incorrecta")).toThrow(
      "Check the password",
    );
    const day = 86_400_000;
    for (const [leaf, message] of [
      [
        {
          from: new Date(Date.now() - 30 * day),
          to: new Date(Date.now() - day),
        },
        "expired",
      ],
      [{ from: new Date(Date.now() + day) }, "not valid yet"],
    ] as const) {
      const dated = fnmtIdentity(join(folder, `leaf-${message}`), {
        givenName: "JUAN",
        surnames: "ESPAÑOL ESPAÑOL",
        password,
        leaf,
      });
      expect(() => openPkcs12(dated.p12, password)).toThrow(message);
    }
  }, 60_000);

  describe("malformed PDFs", () => {
    let pdf: string;

    beforeAll(async () => {
      const document = await PDFDocument.create();
      document.addPage().drawText("Disposable malformed fixture");
      pdf = Buffer.from(
        await document.save({ useObjectStreams: false }),
      ).toString("latin1");
    });

    it.each([
      ["a truncated file", (text: string) => text.slice(0, text.length * 0.8)],
      ["a header without objects", () => "%PDF-1.7\n%%EOF\n"],
    ])("rejects %s", async (_name, damage) => {
      const input = Buffer.from(damage(pdf), "latin1");
      await expect(inspectPdf(input)).rejects.toThrow("valid, unencrypted PDF");
      await expect(
        signPdf(input, openPkcs12(identity.p12, password)),
      ).rejects.toThrow();
    });

    // pdf-lib rebuilds these from their objects. The signed output is a new,
    // well-formed file, so both readers must accept it.
    it.each([
      [
        "a missing cross-reference table",
        (text: string) => `${text.slice(0, text.lastIndexOf("xref"))}%%EOF\n`,
      ],
      [
        "a wrong startxref offset",
        (text: string) => text.replace(/startxref\n\d+/, "startxref\n999999"),
      ],
      ["bytes before the header", (text: string) => `junk\n${text}`],
      ["bytes after %%EOF", (text: string) => `${text}\ngarbage\x00\x01`],
    ])("repairs %s and produces a valid signature", async (_name, damage) => {
      const signed = await signPdf(
        Buffer.from(damage(pdf), "latin1"),
        openPkcs12(identity.p12, password),
      );
      const path = writePdf(signed);
      const result = pdfsig(path, trusted);
      expect(result).toContain("Total document signed");
      expect(result).toContain("Signature is Valid.");
      expect(pyhanko(path, identity.root)).toMatch(/:VALID$/m);
    });
  });
}, 120_000);
