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
    listKeychainIdentities: vi.fn<GarabatoApi["listKeychainIdentities"]>(
      async () => ({
        ok: true,
        value: [
          {
            id: "opaque-1",
            subject: "Keychain signer",
            issuer: "Keychain issuer",
            fingerprint: "def456",
            validFrom: "2026-01-01",
            validTo: "2030-01-01",
          },
        ],
      }),
    ),
    selectKeychainIdentity: vi.fn<GarabatoApi["selectKeychainIdentity"]>(
      async () => ({
        ok: true,
        value: {
          subject: "Keychain signer",
          issuer: "Keychain issuer",
          fingerprint: "def456",
          validFrom: "2026-01-01",
          validTo: "2030-01-01",
        },
      }),
    ),
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

it("signs with a Keychain identity chosen by its opaque reference", async () => {
  const bridge = api();
  const user = userEvent.setup();
  render(<App api={bridge} />);
  await user.click(screen.getByRole("button", { name: "Choose PDF" }));
  await user.click(screen.getByRole("button", { name: "Find in Keychain" }));
  const list = screen.getByRole("list", { name: "Keychain certificates" });
  expect(list.textContent).toContain("Keychain issuer");
  await user.click(screen.getByRole("button", { name: /Keychain signer/ }));
  expect(bridge.selectKeychainIdentity).toHaveBeenCalledWith("opaque-1");
  expect(screen.getByText("Keychain certificate selected")).toBeTruthy();
  expect(screen.queryByLabelText("Certificate password")).toBeNull();
  await user.click(screen.getByRole("button", { name: "Sign and save copy" }));
  expect(await screen.findByText("Signed copy saved")).toBeTruthy();
});

it("shows Keychain denial and cancellation without enabling signing", async () => {
  const bridge = api();
  const user = userEvent.setup();
  render(<App api={bridge} />);
  await user.click(screen.getByRole("button", { name: "Choose PDF" }));
  await user.click(screen.getByRole("button", { name: "Find in Keychain" }));
  await user.click(screen.getByRole("button", { name: /Keychain signer/ }));
  bridge.signAndSave = vi.fn<GarabatoApi["signAndSave"]>(async () => ({
    ok: false,
    error: "Signing was canceled.",
  }));
  await user.click(screen.getByRole("button", { name: "Sign and save copy" }));
  expect(await screen.findByText("Signing was canceled.")).toBeTruthy();
  // The selection stays, so the user can try again after a cancellation.
  expect(screen.getByText("Keychain certificate selected")).toBeTruthy();
});

it("says when the Keychain has no eligible certificates", async () => {
  const bridge = api();
  bridge.listKeychainIdentities = vi.fn<GarabatoApi["listKeychainIdentities"]>(
    async () => ({ ok: true, value: [] }),
  );
  render(<App api={bridge} />);
  fireEvent.click(screen.getByRole("button", { name: "Find in Keychain" }));
  expect(
    await screen.findByText(/No valid RSA signing certificates/),
  ).toBeTruthy();
  expect(
    screen.getByRole<HTMLButtonElement>("button", {
      name: "Sign and save copy",
    }).disabled,
  ).toBe(true);
});

it("does not keep an unlocked file certificate hidden behind the Keychain list", async () => {
  const bridge = api();
  const user = userEvent.setup();
  render(<App api={bridge} />);
  await user.click(screen.getByRole("button", { name: "Choose PDF" }));
  await user.click(screen.getByRole("button", { name: "Choose certificate" }));
  await user.click(screen.getByRole("button", { name: "Unlock certificate" }));
  expect(screen.getByText("Test signer")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Find in Keychain" }));
  expect(screen.queryByText("Test signer")).toBeNull();
  expect(screen.queryByText("Test.p12")).toBeNull();
  expect(
    screen.getByRole<HTMLButtonElement>("button", {
      name: "Sign and save copy",
    }).disabled,
  ).toBe(true);
});
