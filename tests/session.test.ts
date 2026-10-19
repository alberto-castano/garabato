import { beforeEach, expect, it, vi } from "vitest";
import { SigningSession } from "../src/main/session";
import {
  type CertificateProvider,
  inspectPdf,
  openPkcs12,
  signPdf,
} from "../src/main/signing";

function provider(subject: string): CertificateProvider {
  return {
    info: {
      subject,
      issuer: "Test issuer",
      validFrom: "2026-01-01T00:00:00.000Z",
      validTo: "2030-01-01T00:00:00.000Z",
      fingerprint: subject,
    },
    signer: Buffer.from(subject),
    certificates: [Buffer.from(subject)],
    sign: vi.fn(async () => Buffer.from("signature")),
    clear: vi.fn(),
  };
}

vi.mock("../src/main/signing", () => ({
  inspectPdf: vi.fn(async () => ({ pageCount: 1 })),
  openPkcs12: vi.fn((p12: Buffer) => ({
    ...provider("Test signer"),
    clear: () => p12.fill(0),
  })),
  signPdf: vi.fn(async () => Buffer.from("signed")),
}));
beforeEach(() => vi.clearAllMocks());

it("discards a certificate read that finishes after the session closes", () => {
  const session = new SigningSession();
  const generation = session.generation;
  session.reset();
  const bytes = Buffer.from("late certificate");
  expect(() => session.setCertificate(bytes, generation)).toThrow(
    "session has closed",
  );
  expect(bytes.every((byte) => byte === 0)).toBe(true);
  expect(() => session.unlock("")).toThrow("Choose a certificate");
});

it("discards PDF parsing that finishes after the session closes", async () => {
  const session = new SigningSession();
  let finish: (value: { pageCount: number }) => void = () => {
    throw new Error("Parser was not started");
  };
  vi.mocked(inspectPdf).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const bytes = Buffer.from("late PDF");
  const operation = session.setDocument("late.pdf", bytes);
  session.reset();
  finish({ pageCount: 1 });
  await expect(operation).rejects.toThrow("session has closed");
  expect(session.document).toBeUndefined();
  expect(bytes.every((byte) => byte === 0)).toBe(true);
});

it("requires an unlocked certificate and clears it after reset", async () => {
  const session = new SigningSession();
  await session.setDocument("input.pdf", Buffer.from("pdf"));
  const secret = Buffer.from("p12");
  session.setCertificate(secret);
  await expect(session.sign()).rejects.toThrow("certificate first");
  session.unlock("");
  expect(openPkcs12).toHaveBeenCalledWith(secret, "");
  await session.sign();
  expect(signPdf).toHaveBeenCalledWith(
    Buffer.from("pdf"),
    expect.objectContaining({ signer: Buffer.from("Test signer") }),
  );
  session.reset();
  expect(secret.every((byte) => byte === 0)).toBe(true);
  await expect(session.sign()).rejects.toThrow("certificate first");
  expect(session.document).toBeUndefined();
});

it("invalidates the old unlock when replacing a certificate or unlocking fails", async () => {
  const session = new SigningSession();
  await session.setDocument("input.pdf", Buffer.from("pdf"));
  session.setCertificate(Buffer.from("first"));
  session.unlock("first password");
  session.setCertificate(Buffer.from("second"));
  await expect(session.sign()).rejects.toThrow("certificate first");
  session.unlock("second password");
  vi.mocked(openPkcs12).mockImplementationOnce(() => {
    throw new Error("Wrong password");
  });
  expect(() => session.unlock("wrong")).toThrow("Wrong password");
  await expect(session.sign()).rejects.toThrow("certificate first");
});

it("gives the renderer opaque Keychain references and signs with the chosen one", async () => {
  const session = new SigningSession();
  await session.setDocument("input.pdf", Buffer.from("pdf"));
  const first = provider("First");
  const second = provider("Second");
  const listed = session.setKeychainIdentities([first, second]);
  expect(listed.map(({ subject }) => subject)).toEqual(["First", "Second"]);
  for (const { id } of listed) {
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(id).not.toContain("First");
  }
  expect(Object.keys(listed[0]).sort()).toEqual(
    ["id", "subject", "issuer", "validFrom", "validTo", "fingerprint"].sort(),
  );
  expect(session.selectKeychainIdentity(listed[1].id).subject).toBe("Second");
  await session.sign();
  expect(signPdf).toHaveBeenCalledWith(Buffer.from("pdf"), second);
});

it("rejects unknown, stale, and closed-session Keychain references", () => {
  const session = new SigningSession();
  const [old] = session.setKeychainIdentities([provider("Old")]);
  session.setKeychainIdentities([provider("New")]);
  expect(() => session.selectKeychainIdentity(old.id)).toThrow("again");
  expect(() => session.selectKeychainIdentity(42)).toThrow("again");
  const [current] = session.setKeychainIdentities([provider("Current")]);
  const generation = session.generation;
  session.reset();
  expect(() => session.selectKeychainIdentity(current.id)).toThrow("again");
  expect(() =>
    session.setKeychainIdentities([provider("Late")], generation),
  ).toThrow("session has closed");
});

it("clears the current certificate when the user lists the Keychain", async () => {
  const session = new SigningSession();
  await session.setDocument("input.pdf", Buffer.from("pdf"));
  const secret = Buffer.from("p12");
  session.setCertificate(secret);
  session.unlock("");
  session.setKeychainIdentities([]);
  expect(secret.every((byte) => byte === 0)).toBe(true);
  await expect(session.sign()).rejects.toThrow("certificate first");
});
