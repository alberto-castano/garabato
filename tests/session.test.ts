import { beforeEach, expect, it, vi } from "vitest";
import { SigningSession } from "../src/main/session";
import { inspectCertificate, inspectPdf, signPdf } from "../src/main/signing";

vi.mock("../src/main/signing", () => ({
  inspectPdf: vi.fn(async () => ({ pageCount: 1 })),
  inspectCertificate: vi.fn(() => ({ subject: "Test signer" })),
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
  await expect(session.sign()).rejects.toThrow("unlock");
  session.unlock("");
  await session.sign();
  expect(signPdf).toHaveBeenCalledWith(Buffer.from("pdf"), secret, "");
  session.reset();
  expect(secret.every((byte) => byte === 0)).toBe(true);
  await expect(session.sign()).rejects.toThrow("unlock");
  expect(session.document).toBeUndefined();
});

it("invalidates the old password when replacing a certificate or unlocking fails", async () => {
  const session = new SigningSession();
  await session.setDocument("input.pdf", Buffer.from("pdf"));
  session.setCertificate(Buffer.from("first"));
  session.unlock("first password");
  session.setCertificate(Buffer.from("second"));
  await expect(session.sign()).rejects.toThrow("unlock");
  session.unlock("second password");
  vi.mocked(inspectCertificate).mockImplementationOnce(() => {
    throw new Error("Wrong password");
  });
  expect(() => session.unlock("wrong")).toThrow("Wrong password");
  await expect(session.sign()).rejects.toThrow("unlock");
});
