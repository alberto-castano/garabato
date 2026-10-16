import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { beforeAll, expect, it, vi } from "vitest";
import type { Result } from "../src/shared/contracts";

const mocks = vi.hoisted(() => {
  const frame = { url: "" };
  const contents = {
    mainFrame: frame,
    setWindowOpenHandler: vi.fn(),
    on: vi.fn(),
    session: {
      setPermissionRequestHandler: vi.fn(),
      setPermissionCheckHandler: vi.fn(),
    },
  };
  return {
    contents,
    handlers: new Map<
      string,
      (event: unknown, argument?: unknown) => Promise<Result<unknown>>
    >(),
    open: vi.fn(async () => ({ canceled: true, filePaths: [] })),
  };
});

vi.mock("electron", () => ({
  app: {
    isPackaged: true,
    whenReady: () => Promise.resolve(),
    on: vi.fn(),
    quit: vi.fn(),
  },
  BrowserWindow: class {
    webContents = mocks.contents;
    setMenuBarVisibility() {}
    on() {}
    loadFile() {
      return Promise.resolve();
    }
  },
  dialog: { showOpenDialog: mocks.open },
  ipcMain: {
    handle: (
      channel: string,
      handler: (event: unknown, argument?: unknown) => Promise<Result<unknown>>,
    ) => mocks.handlers.set(channel, handler),
  },
}));

beforeAll(async () => {
  await import("../src/main/index");
  mocks.contents.mainFrame.url = pathToFileURL(
    resolve("src/renderer/index.html"),
  ).href;
});

function choose(event: unknown) {
  const handler = mocks.handlers.get("document:choose");
  if (!handler) throw new Error("Missing handler");
  return handler(event);
}

it("allows the application main frame to open a native dialog", async () => {
  const result = await choose({
    sender: mocks.contents,
    senderFrame: mocks.contents.mainFrame,
  });
  expect(result).toEqual({ ok: true, value: null });
  expect(mocks.open).toHaveBeenCalledTimes(1);
});

it("rejects foreign windows and child frames before opening a file dialog", async () => {
  mocks.open.mockClear();
  expect(
    (await choose({ sender: {}, senderFrame: mocks.contents.mainFrame })).ok,
  ).toBe(false);
  expect(
    (
      await choose({
        sender: mocks.contents,
        senderFrame: { ...mocks.contents.mainFrame },
      })
    ).ok,
  ).toBe(false);
  expect(mocks.open).not.toHaveBeenCalled();
});

it("rejects a frame that has navigated away from the application", async () => {
  const original = mocks.contents.mainFrame.url;
  mocks.contents.mainFrame.url = "https://example.com/";
  try {
    expect(
      (
        await choose({
          sender: mocks.contents,
          senderFrame: mocks.contents.mainFrame,
        })
      ).ok,
    ).toBe(false);
    expect(mocks.open).not.toHaveBeenCalled();
  } finally {
    mocks.contents.mainFrame.url = original;
  }
});
