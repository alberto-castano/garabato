import { beforeEach, expect, it, vi } from "vitest";
import { SigningSession } from "../src/main/session";
import {
  inspectCertificate,
  inspectPdf,
  previewBox,
  signPdf,
} from "../src/main/signing";

vi.mock("../src/main/signing", async (importOriginal) => ({
  parsePlacement: (await importOriginal<typeof import("../src/main/signing")>())
    .parsePlacement,
  inspectPdf: vi.fn(async () => ({ pageCount: 1 })),
  inspectCertificate: vi.fn(() => ({
    subject: "CN=Test signer",
    signer: "Test signer",
  })),
  previewBox: vi.fn(async () => Buffer.from("preview")),
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
  expect(signPdf).toHaveBeenCalledWith(Buffer.from("pdf"), secret, "", null);
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

it("previews and signs with a checked placement and the unlocked signer", async () => {
  const session = new SigningSession();
  const placement = { page: 0, x: 0.1, y: 0.1, width: 0.3, height: 0.1 };
  await session.setDocument("input.pdf", Buffer.from("pdf"));
  session.setCertificate(Buffer.from("p12"));
  await expect(session.preview(placement)).rejects.toThrow("unlock");
  session.unlock("");
  await expect(session.preview(null)).rejects.toThrow(
    "Place the signature box",
  );
  await expect(session.preview({ ...placement, x: 0.9 })).rejects.toThrow(
    "inside the page",
  );
  await session.preview(placement);
  expect(previewBox).toHaveBeenCalledWith(
    Buffer.from("pdf"),
    placement,
    "Test signer",
  );
  await expect(session.sign({ ...placement, width: -1 })).rejects.toThrow(
    "inside the page",
  );
  expect(signPdf).not.toHaveBeenCalled();
  await session.sign({ ...placement, extra: "ignored" });
  expect(signPdf).toHaveBeenCalledWith(
    Buffer.from("pdf"),
    Buffer.from("p12"),
    "",
    placement,
  );
  session.clearCertificate();
  await expect(session.preview(placement)).rejects.toThrow("unlock");
});
