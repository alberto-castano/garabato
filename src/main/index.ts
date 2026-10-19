import { basename, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { app, BrowserWindow, dialog, ipcMain } from "electron";
import type { Result } from "../shared/contracts";
import { readBoundedFile, saveNewFile } from "./files";
import { SigningSession } from "./session";
import { MAX_P12_BYTES, MAX_PDF_BYTES, parsePlacement } from "./signing";

const here = dirname(fileURLToPath(import.meta.url));
const rendererFile = join(here, "../renderer/index.html");
const devUrl = !app.isPackaged ? process.env.ELECTRON_RENDERER_URL : undefined;
const rendererUrl = devUrl
  ? new URL(devUrl).href
  : pathToFileURL(rendererFile).href;
const signing = new SigningSession();
let window: BrowserWindow | null = null;
let busy = false;

function registerHandler<T>(
  channel: string,
  action: (argument: unknown, generation: number) => Promise<T>,
) {
  ipcMain.handle(
    channel,
    async (event, argument: unknown): Promise<Result<T>> => {
      if (
        !window ||
        event.sender !== window.webContents ||
        event.senderFrame !== window.webContents.mainFrame ||
        event.senderFrame.url !== rendererUrl
      ) {
        return {
          ok: false,
          error: "This request did not come from the application.",
        };
      }
      if (busy)
        return {
          ok: false,
          error: "Wait for the current operation to finish.",
        };
      busy = true;
      try {
        return { ok: true, value: await action(argument, signing.generation) };
      } catch (error) {
        return {
          ok: false,
          error:
            error instanceof Error ? error.message : "The operation failed.",
        };
      } finally {
        busy = false;
      }
    },
  );
}

async function chooseFile(extensions: string[]): Promise<string | null> {
  if (!window) return null;
  const result = await dialog.showOpenDialog(window, {
    properties: ["openFile"],
    filters: [{ name: "Supported files", extensions }],
  });
  return result.canceled ? null : (result.filePaths[0] ?? null);
}

registerHandler("document:choose", async (_argument, generation) => {
  const path = await chooseFile(["pdf"]);
  if (!path) return null;
  let bytes: Buffer;
  try {
    bytes = await readBoundedFile(path, MAX_PDF_BYTES);
  } catch {
    throw new Error("Could not read this PDF. Choose a file under 25 MiB.");
  }
  const document = await signing.setDocument(basename(path), bytes, generation);
  // The renderer gets its own copy for preview; the session keeps the original.
  return { ...document, data: new Uint8Array(bytes) };
});

registerHandler("certificate:choose", async (_argument, generation) => {
  const path = await chooseFile(["p12", "pfx"]);
  if (!path) return null;
  let bytes: Buffer;
  try {
    bytes = await readBoundedFile(path, MAX_P12_BYTES);
  } catch {
    throw new Error(
      "Could not read this certificate. Choose a file under 2 MiB.",
    );
  }
  signing.setCertificate(bytes, generation);
  return { name: basename(path) };
});

registerHandler("certificate:unlock", async (password) =>
  signing.unlock(password),
);
registerHandler("session:reset", async () => {
  signing.reset();
  return null;
});
registerHandler("document:preview", async (placement, generation) => {
  const bytes = await signing.preview(placement);
  signing.assertActive(generation);
  return new Uint8Array(bytes);
});
registerHandler("document:sign", async (placement, generation) => {
  if (!window || !signing.document) throw new Error("Choose a PDF first.");
  // Reject a bad placement before the save dialog opens.
  parsePlacement(placement);
  const result = await dialog.showSaveDialog(window, {
    title: "Save signed copy",
    defaultPath: `${signing.document.name.replace(/\.pdf$/i, "")}-signed.pdf`,
    filters: [{ name: "PDF document", extensions: ["pdf"] }],
  });
  if (result.canceled || !result.filePath) return null;
  signing.assertActive(generation);
  const bytes = await signing.sign(placement);
  signing.assertActive(generation);
  try {
    await saveNewFile(result.filePath, bytes);
  } catch {
    throw new Error(
      "Could not save the copy. Choose a new filename in a writable folder.",
    );
  }
  const saved = { name: basename(result.filePath), bytes: bytes.length };
  signing.clearCertificate();
  return saved;
});

function createWindow() {
  window = new BrowserWindow({
    title: "Garabato",
    width: 1120,
    height: 820,
    minWidth: 620,
    minHeight: 640,
    backgroundColor: "#f6f5f1",
    webPreferences: {
      preload: join(here, "../preload/index.cjs"),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  window.setMenuBarVisibility(false);
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event) => event.preventDefault());
  window.webContents.on("will-attach-webview", (event) =>
    event.preventDefault(),
  );
  window.webContents.on("render-process-gone", () => signing.reset());
  window.webContents.session.setPermissionRequestHandler(
    (_contents, _permission, callback) => callback(false),
  );
  window.webContents.session.setPermissionCheckHandler(() => false);
  window.on("closed", () => {
    signing.reset();
    window = null;
  });
  if (devUrl) void window.loadURL(devUrl);
  else void window.loadFile(rendererFile);
}

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (!window) createWindow();
  });
});
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
app.on("before-quit", () => signing.reset());
