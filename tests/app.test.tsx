// @vitest-environment jsdom
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../src/renderer/src/App";
import type { GarabatoApi } from "../src/shared/contracts";

afterEach(cleanup);

function api(): GarabatoApi {
  return {
    choosePdf: vi.fn<GarabatoApi["choosePdf"]>(async () => ({
      ok: true,
      value: { name: "Example.pdf", pageCount: 2, bytes: 1200 },
    })),
    chooseCertificate: vi.fn<GarabatoApi["chooseCertificate"]>(async () => ({
      ok: true,
      value: { name: "Test.p12" },
    })),
    unlockCertificate: vi.fn<GarabatoApi["unlockCertificate"]>(async () => ({
      ok: true,
      value: {
        subject: "Test signer",
        issuer: "Test issuer",
        fingerprint: "abc123",
        validFrom: "2026-01-01",
        validTo: "2030-01-01",
      },
    })),
    signAndSave: vi.fn<GarabatoApi["signAndSave"]>(async () => ({
      ok: true,
      value: { name: "Example-signed.pdf", bytes: 2500 },
    })),
    reset: vi.fn<GarabatoApi["reset"]>(async () => ({ ok: true, value: null })),
  };
}

it("requires document and certificate review before signing and clears the password", async () => {
  const bridge = api();
  const user = userEvent.setup();
  render(<App api={bridge} />);
  expect(
    screen.getByRole<HTMLButtonElement>("button", {
      name: "Sign and save copy",
    }).disabled,
  ).toBe(true);
  await user.click(screen.getByRole("button", { name: "Choose PDF" }));
  await user.click(screen.getByRole("button", { name: "Choose certificate" }));
  await user.type(screen.getByLabelText("Certificate password"), "secret");
  await user.click(screen.getByRole("button", { name: "Unlock certificate" }));
  expect(bridge.unlockCertificate).toHaveBeenCalledWith("secret");
  expect(screen.queryByLabelText("Certificate password")).toBeNull();
  expect(screen.getByText("Test signer")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Sign and save copy" }));
  expect(await screen.findByText("Signed copy saved")).toBeTruthy();
  expect(bridge.signAndSave).toHaveBeenCalledTimes(1);
  await user.click(
    screen.getByRole("button", { name: "Sign another document" }),
  );
  expect(bridge.reset).toHaveBeenCalledTimes(1);
  expect(screen.queryByText("Test signer")).toBeNull();
});

it("shows password errors, clears the password, and does not enable signing", async () => {
  const bridge = api();
  bridge.unlockCertificate = vi.fn<GarabatoApi["unlockCertificate"]>(
    async () => ({
      ok: false,
      error: "Check the password.",
    }),
  );
  render(<App api={bridge} />);
  fireEvent.click(screen.getByRole("button", { name: "Choose certificate" }));
  const input = await screen.findByLabelText<HTMLInputElement>(
    "Certificate password",
  );
  fireEvent.change(input, { target: { value: "wrong" } });
  fireEvent.click(screen.getByRole("button", { name: "Unlock certificate" }));
  expect(await screen.findByText("Check the password.")).toBeTruthy();
  expect(input.value).toBe("");
  expect(
    screen.getByRole<HTMLButtonElement>("button", {
      name: "Sign and save copy",
    }).disabled,
  ).toBe(true);
});

it("preserves the selected PDF when the native file dialog is canceled", async () => {
  const bridge = api();
  render(<App api={bridge} />);
  fireEvent.click(screen.getByRole("button", { name: "Choose PDF" }));
  expect(await screen.findByText("Example.pdf")).toBeTruthy();
  bridge.choosePdf = vi.fn<GarabatoApi["choosePdf"]>(async () => ({
    ok: true,
    value: null,
  }));
  fireEvent.click(screen.getByRole("button", { name: "Change PDF" }));
  await waitFor(() => expect(bridge.choosePdf).toHaveBeenCalled());
  expect(screen.getByText("Example.pdf")).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
});

it("does not pretend to sign when opened outside Electron", () => {
  render(<App />);
  expect(screen.getByText("Open the desktop app to sign")).toBeTruthy();
  expect(
    screen.getByRole<HTMLButtonElement>("button", { name: "Choose PDF" })
      .disabled,
  ).toBe(true);
});
