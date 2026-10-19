import { spawnSync } from "node:child_process";
import { createHash, randomBytes, verify, X509Certificate } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { PDFDocument } from "@cantoo/pdf-lib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type KeychainOptions,
  listKeychainIdentities,
} from "../src/main/keychain";
import {
  CertificateError,
  type CertificateProvider,
  signPdf,
} from "../src/main/signing";
import { fnmtIdentity, openssl } from "./support/fnmt";

const folder = mkdtempSync(join(tmpdir(), "garabato-keychain-test-"));
afterAll(() => rmSync(folder, { recursive: true, force: true }));
let fileCount = 0;

function run(command: string, args: string[]): string {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`${command} ${args.join(" ")}\n${result.stderr}`);
  return result.stdout + result.stderr;
}

async function simplePdf(): Promise<Buffer> {
  const document = await PDFDocument.create();
  document.addPage().drawText("Disposable Keychain fixture");
  return Buffer.from(await document.save());
}

/** A disposable FNMT-like identity: the signer DER and its files. */
function identity(givenName: string) {
  const path = join(folder, givenName);
  fnmtIdentity(path, { givenName, surnames: "PRUEBAS", password: "unused" });
  const signer = new X509Certificate(readFileSync(join(path, "leaf.pem"))).raw;
  return { path, signer };
}

/** A stand-in helper that answers list and sign with fixed responses. */
function fakeHelper(list: unknown, sign: unknown): string {
  fileCount += 1;
  const path = join(folder, `fake-helper-${fileCount}`);
  writeFileSync(
    path,
    [
      "#!/bin/sh",
      'case "$(cat)" in',
      `  *'"command":"sign"'*) printf '%s' '${JSON.stringify(sign)}' ;;`,
      `  *) printf '%s' '${JSON.stringify(list)}' ;;`,
      "esac",
    ].join("\n"),
  );
  chmodSync(path, 0o700);
  return path;
}

describe("Keychain provider", () => {
  const { signer } = identity("FALSO");
  const listing = {
    ok: true,
    identities: [{ certificates: [signer.toString("base64")] }],
  };

  it("exposes public certificate metadata and signs through the helper", async () => {
    const [provider] = await listKeychainIdentities({
      helper: fakeHelper(listing, {
        ok: true,
        signature: Buffer.from("signature").toString("base64"),
      }),
    });
    expect(provider.info.subject).toContain("CN=PRUEBAS FALSO - 99999999R");
    expect(provider.info.fingerprint).toBe(
      createHash("sha256").update(signer).digest("hex"),
    );
    expect(provider.signer).toEqual(signer);
    expect(await provider.sign(Buffer.from("data"))).toEqual(
      Buffer.from("signature"),
    );
  });

  it("omits expired identities", async () => {
    const expired = join(folder, "expired");
    fnmtIdentity(expired, {
      givenName: "CADUCADO",
      surnames: "PRUEBAS",
      password: "unused",
      leaf: { to: new Date(Date.now() - 1000) },
    });
    const der = new X509Certificate(readFileSync(join(expired, "leaf.pem")))
      .raw;
    const providers = await listKeychainIdentities({
      helper: fakeHelper(
        {
          ok: true,
          identities: [
            { certificates: [der.toString("base64")] },
            ...listing.identities,
          ],
        },
        {},
      ),
    });
    expect(providers.map(({ signer }) => signer)).toEqual([signer]);
  });

  it.each([
    ["canceled", -128, "Signing was canceled."],
    ["denied", -25293, "did not allow Garabato"],
    ["locked", -25293, "keychain is locked"],
    ["interaction-not-allowed", -25308, "could not ask for permission"],
    ["not-found", -25300, "no longer in the Keychain"],
    ["unexpected", -1, "could not complete the request"],
  ])("reports %s through PDF signing", async (code, status, message) => {
    const [provider] = await listKeychainIdentities({
      helper: fakeHelper(listing, { ok: false, code, status }),
    });
    const failure = await signPdf(await simplePdf(), provider).catch(
      (error: unknown) => error,
    );
    // Not the generic "Signing failed" message.
    expect(failure).toBeInstanceOf(CertificateError);
    expect((failure as Error).message).toContain(message);
  });

  it("rejects a missing helper and malformed output", async () => {
    await expect(
      listKeychainIdentities({ helper: join(folder, "missing") }),
    ).rejects.toThrow("Cannot start the Keychain helper.");
    await expect(
      listKeychainIdentities({ helper: fakeHelper("not json", {}) }),
    ).rejects.toThrow("The Keychain helper failed.");
    await expect(
      listKeychainIdentities({ helper: fakeHelper({ ok: true }, {}) }),
    ).rejects.toThrow("The Keychain helper failed.");
  });
});

// Uses a disposable keychain file. The user's keychains and search list are
// not changed. Prompts are disabled, so macOS fails instead of asking.
describe.runIf(process.platform === "darwin")("macOS Keychain", () => {
  const helper = join(folder, "garabato-keychain");
  const keychain = join(folder, "test.keychain-db");
  const keychainPassword = randomBytes(18).toString("base64");
  const options: KeychainOptions = { helper, keychain, interactive: false };
  const allowed = identity("PERMITIDO");
  const refused = identity("DENEGADO");
  let providers: CertificateProvider[];

  /** Imports a legacy-encrypted PKCS#12, which every macOS version reads. */
  function importIdentity(path: string, allowHelper: boolean) {
    const p12 = join(path, "keychain.p12");
    openssl([
      ...["pkcs12", "-export", "-legacy", "-inkey", join(path, "leaf.key")],
      ...["-in", join(path, "leaf.pem"), "-passout", "pass:import"],
      ...["-out", p12],
    ]);
    run("security", [
      ...["import", p12, "-k", keychain, "-f", "pkcs12", "-P", "import"],
      ...(allowHelper ? ["-T", helper] : []),
    ]);
  }

  function find(provider: { signer: Buffer }): CertificateProvider {
    const found = providers.find(({ signer }) =>
      signer.equals(provider.signer),
    );
    if (!found) throw new Error("Identity was not listed");
    return found;
  }

  beforeAll(async () => {
    run("sh", [resolve("scripts/build-keychain.sh"), helper]);
    const searchList = run("security", ["list-keychains", "-d", "user"])
      .split("\n")
      .map((line) => line.trim().replace(/^"|"$/g, ""))
      .filter(Boolean);
    try {
      run("security", ["create-keychain", "-p", keychainPassword, keychain]);
    } finally {
      // create-keychain can add the file to the user's search list.
      run("security", ["list-keychains", "-d", "user", "-s", ...searchList]);
    }
    run("security", ["set-keychain-settings", keychain]);
    run("security", ["unlock-keychain", "-p", keychainPassword, keychain]);
    importIdentity(allowed.path, true);
    importIdentity(refused.path, false);
    // An EC identity is not eligible.
    const ec = join(folder, "ec");
    mkdirSync(ec);
    openssl([
      ...["req", "-x509", "-newkey", "ec", "-pkeyopt"],
      ...["ec_paramgen_curve:P-256", "-nodes", "-days", "1"],
      ...["-subj", "/CN=EC PRUEBAS", "-keyout", join(ec, "leaf.key")],
      ...["-out", join(ec, "leaf.pem")],
    ]);
    importIdentity(ec, true);
    providers = await listKeychainIdentities(options);
  }, 120_000);

  afterAll(() => {
    spawnSync("security", ["delete-keychain", keychain]);
  });

  it("lists RSA identities only", () => {
    expect(providers.map(({ info }) => info.subject).sort()).toEqual([
      expect.stringContaining("DENEGADO"),
      expect.stringContaining("PERMITIDO"),
    ]);
    expect(find(allowed).certificates[0]).toEqual(allowed.signer);
  });

  it("signs with the Keychain key, verified independently", async () => {
    const provider = find(allowed);
    const data = Buffer.from("Datos de prueba");
    const signature = await provider.sign(data);
    const { publicKey } = new X509Certificate(allowed.signer);
    expect(verify("sha256", data, publicKey, signature)).toBe(true);

    const pdf = join(folder, "signed.pdf");
    writeFileSync(pdf, await signPdf(await simplePdf(), provider));
    const nss = join(folder, "nss");
    mkdirSync(nss);
    run("certutil", ["-N", "-d", `sql:${nss}`, "--empty-password"]);
    const result = spawnSync("pdfsig", ["-nssdir", `sql:${nss}`, pdf], {
      encoding: "utf8",
    });
    expect(result.stdout).toContain(
      "Signature Validation: Signature is Valid.",
    );
  });

  it("reports a locked keychain", async () => {
    run("security", ["lock-keychain", keychain]);
    try {
      await expect(find(allowed).sign(Buffer.from("data"))).rejects.toThrow(
        "The keychain is locked.",
      );
    } finally {
      run("security", ["unlock-keychain", "-p", keychainPassword, keychain]);
    }
  });

  it("reports denial when the key does not allow the helper", async () => {
    await expect(find(refused).sign(Buffer.from("data"))).rejects.toThrow(
      "did not allow Garabato",
    );
  });

  it("reports an identity removed after listing", async () => {
    const provider = find(refused);
    const sha1 = createHash("sha1").update(refused.signer).digest("hex");
    run("security", ["delete-identity", "-Z", sha1, keychain]);
    await expect(provider.sign(Buffer.from("data"))).rejects.toThrow(
      "no longer in the Keychain",
    );
  });
});
