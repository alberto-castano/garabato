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

const pdfjs = vi.hoisted(() => {
  // A stand-in for pdf.js: every page is 600 x 800 points.
  const page = {
    getViewport: ({ scale }: { scale: number }) => ({
      width: 600 * scale,
      height: 800 * scale,
    }),
    render: () => ({ promise: Promise.resolve(), cancel: () => {} }),
  };
  const document = () => ({
    getPage: async () => page,
    loadingTask: { destroy: async () => {} },
  });
  return { document, openPdf: vi.fn(async () => document()) };
});
vi.mock("../src/renderer/src/lib/pdf", () => ({ openPdf: pdfjs.openPdf }));

afterEach(() => {
  cleanup();
  pdfjs.openPdf.mockImplementation(async () => pdfjs.document());
});

function api(): GarabatoApi {
  return {
    choosePdf: vi.fn<GarabatoApi["choosePdf"]>(async () => ({
      ok: true,
      value: {
        name: "Example.pdf",
        pageCount: 2,
        bytes: 1200,
        data: new Uint8Array([37, 80, 68, 70]),
      },
    })),
    chooseCertificate: vi.fn<GarabatoApi["chooseCertificate"]>(async () => ({
      ok: true,
      value: { name: "Test.p12" },
    })),
    unlockCertificate: vi.fn<GarabatoApi["unlockCertificate"]>(async () => ({
      ok: true,
      value: {
        subject: "CN=Test signer, C=ES",
        signer: "Test signer",
        issuer: "Test issuer",
        fingerprint: "abc123",
        validFrom: "2026-01-01",
        validTo: "2030-01-01",
      },
    })),
    previewSignature: vi.fn<GarabatoApi["previewSignature"]>(async () => ({
      ok: true,
      value: new Uint8Array([37, 80, 68, 70]),
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
      name: "Review and sign",
    }).disabled,
  ).toBe(true);
  await user.click(screen.getByRole("button", { name: "Choose PDF" }));
  await user.click(screen.getByRole("button", { name: "Choose certificate" }));
  await user.type(screen.getByLabelText("Certificate password"), "secret");
  await user.click(screen.getByRole("button", { name: "Unlock certificate" }));
  expect(bridge.unlockCertificate).toHaveBeenCalledWith("secret");
  expect(screen.queryByLabelText("Certificate password")).toBeNull();
  expect(screen.getByText("CN=Test signer, C=ES")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Review and sign" }));
  expect(await screen.findByText("No visible box")).toBeTruthy();
  expect(screen.getByText("Test signer")).toBeTruthy();
  expect(bridge.previewSignature).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Sign and save copy" }));
  expect(await screen.findByText("Signed copy saved")).toBeTruthy();
  expect(bridge.signAndSave).toHaveBeenCalledExactlyOnceWith(null);
  await user.click(
    screen.getByRole("button", { name: "Sign another document" }),
  );
  expect(bridge.reset).toHaveBeenCalledTimes(1);
  expect(screen.queryByText("CN=Test signer, C=ES")).toBeNull();
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
      name: "Review and sign",
    }).disabled,
  ).toBe(true);
});

async function openDocument(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Choose PDF" }));
  const add = await screen.findByRole<HTMLButtonElement>("button", {
    name: "Add signature box",
  });
  await waitFor(() => expect(add.disabled).toBe(false));
  return add;
}

async function unlock(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Choose certificate" }));
  await user.click(screen.getByRole("button", { name: "Unlock certificate" }));
  await screen.findByText("Certificate unlocked");
}

it("places, moves, resizes, and removes the signature box with the keyboard", async () => {
  const user = userEvent.setup();
  render(<App api={api()} />);
  const add = await openDocument(user);
  await user.click(add);
  const box = screen.getByRole("button", { name: "Signature box on page 1" });
  expect(document.activeElement).toBe(box);
  // The default box is 180 x 54 points in the lower-right corner.
  expect(
    screen.getByText(
      "Box on page 1, 64% from the left and 85% from the top, 180 × 54 points.",
    ),
  ).toBeTruthy();
  await user.keyboard("{ArrowRight}{ArrowRight}{ArrowUp}");
  await user.keyboard("{Shift>}{ArrowDown}{ArrowLeft}{/Shift}");
  expect(
    screen.getByText(
      "Box on page 1, 66% from the left and 84% from the top, 174 × 62 points.",
    ),
  ).toBeTruthy();
  // The box stays inside the page.
  for (let step = 0; step < 50; step += 1) await user.keyboard("{ArrowRight}");
  expect(screen.getByText(/^Box on page 1, 71% from the left/)).toBeTruthy();
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("button", { name: /^Signature box/ })).toBeNull();
  expect(
    screen.getByText("No visible box. The signature will be invisible."),
  ).toBeTruthy();
  expect(document.activeElement).toBe(
    screen.getByRole("button", { name: "Add signature box" }),
  );
});

it("selects pages and zooms the preview", async () => {
  const user = userEvent.setup();
  render(<App api={api()} />);
  await openDocument(user);
  const page = () =>
    screen.getByRole("img", { name: /^Page \d of 2$/ }).parentElement;
  expect(page()?.style.width).toBe("450px");
  await user.click(screen.getByRole("button", { name: "Zoom in" }));
  expect(screen.getByRole("status", { name: "Zoom level" }).textContent).toBe(
    "100%",
  );
  await waitFor(() => expect(page()?.style.width).toBe("600px"));
  await user.click(screen.getByRole("button", { name: "Zoom out" }));
  await user.click(screen.getByRole("button", { name: "Zoom out" }));
  expect(
    screen.getByRole<HTMLButtonElement>("button", { name: "Zoom out" })
      .disabled,
  ).toBe(true);
  await waitFor(() => expect(page()?.style.width).toBe("300px"));

  await user.click(screen.getByRole("button", { name: "Next page" }));
  expect(screen.getByText("Page 2 of 2")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Add signature box" }));
  expect(
    screen.getByRole("button", { name: "Signature box on page 2" }),
  ).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Previous page" }));
  expect(screen.queryByRole("button", { name: /^Signature box/ })).toBeNull();
  expect(screen.getByText("Box on page 2.")).toBeTruthy();
  await user.click(
    screen.getByRole("button", { name: "Move box to this page" }),
  );
  expect(
    screen.getByRole("button", { name: "Signature box on page 1" }),
  ).toBeTruthy();
});

it("shows the drawn box and signer before signing, and Back cancels", async () => {
  const bridge = api();
  const user = userEvent.setup();
  render(<App api={bridge} />);
  await user.click(await openDocument(user));
  await unlock(user);
  await user.click(screen.getByRole("button", { name: "Review and sign" }));
  const placement = { page: 0, x: 0.64, y: 0.8525, width: 0.3, height: 0.0675 };
  const sent = vi.mocked(bridge.previewSignature).mock.calls[0][0];
  for (const [key, value] of Object.entries(placement))
    expect(sent[key as keyof typeof sent]).toBeCloseTo(value);
  expect(
    await screen.findByRole("img", {
      name: "Final preview of page 1 with the signature box",
    }),
  ).toBeTruthy();
  expect(screen.getByText("Test signer")).toBeTruthy();
  expect(screen.getByText("The box is not the proof")).toBeTruthy();

  await user.click(screen.getByRole("button", { name: "Back" }));
  expect(bridge.signAndSave).not.toHaveBeenCalled();
  expect(
    screen.getByRole("button", { name: "Signature box on page 1" }),
  ).toBeTruthy();

  await user.click(screen.getByRole("button", { name: "Review and sign" }));
  // A canceled save dialog keeps the review open.
  vi.mocked(bridge.signAndSave).mockResolvedValueOnce({
    ok: true,
    value: null,
  });
  await user.click(
    await screen.findByRole("button", { name: "Sign and save copy" }),
  );
  expect(screen.getByRole("button", { name: "Back" })).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Sign and save copy" }));
  expect(await screen.findByText("Signed copy saved")).toBeTruthy();
  expect(bridge.signAndSave).toHaveBeenLastCalledWith(sent);
});

it("still signs without a visible box when the preview cannot open", async () => {
  pdfjs.openPdf.mockRejectedValue(new Error("Invalid PDF structure"));
  const bridge = api();
  const user = userEvent.setup();
  render(<App api={bridge} />);
  await user.click(screen.getByRole("button", { name: "Choose PDF" }));
  expect(await screen.findByText("Preview is not available")).toBeTruthy();
  await unlock(user);
  await user.click(screen.getByRole("button", { name: "Review and sign" }));
  await user.click(
    await screen.findByRole("button", { name: "Sign and save copy" }),
  );
  expect(bridge.signAndSave).toHaveBeenCalledExactlyOnceWith(null);
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
