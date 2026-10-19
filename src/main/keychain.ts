import { spawn } from "node:child_process";
import {
  CertificateError,
  type CertificateProvider,
  describeCertificate,
} from "./signing";

export interface KeychainOptions {
  /** Path of the garabato-keychain helper (native/keychain/main.swift). */
  helper: string;
  /** Search only this keychain file, not the user's search list. For tests. */
  keychain?: string;
  /** false makes macOS fail instead of showing a prompt. For tests. */
  interactive?: boolean;
}

// Responses hold certificates and signatures only; this is a generous bound.
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const LIST_TIMEOUT_MS = 30_000;
// Signing can wait for the user to answer a macOS prompt.
const SIGN_TIMEOUT_MS = 5 * 60_000;

const messages: Record<string, string> = {
  canceled: "Signing was canceled.",
  denied:
    "macOS did not allow Garabato to use this private key. Choose Allow when macOS asks, then try again.",
  locked: "The keychain is locked. Unlock it, then try again.",
  "interaction-not-allowed":
    "macOS could not ask for permission to use this private key. Unlock the keychain, then try again.",
  "not-found":
    "This certificate is no longer in the Keychain. Find your certificates again.",
  "no-keychain": "The keychain is not available.",
};

function run(
  options: KeychainOptions,
  request: Record<string, unknown>,
  timeout: number,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const child = spawn(options.helper, [], {
      stdio: ["pipe", "pipe", "ignore"],
      timeout,
    });
    const chunks: Buffer[] = [];
    let size = 0;
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_OUTPUT_BYTES) child.kill();
      else chunks.push(chunk);
    });
    child.stdin.on("error", () => undefined);
    child.on("error", () =>
      reject(new CertificateError("Cannot start the Keychain helper.")),
    );
    child.on("close", (_code, signal) => {
      if (signal) {
        reject(
          new CertificateError(
            size > MAX_OUTPUT_BYTES
              ? "The Keychain helper failed."
              : "The Keychain did not respond in time. Try again.",
          ),
        );
        return;
      }
      try {
        const response: unknown = JSON.parse(Buffer.concat(chunks).toString());
        if (typeof response !== "object" || response === null) throw response;
        resolve(response as Record<string, unknown>);
      } catch {
        reject(new CertificateError("The Keychain helper failed."));
      }
    });
    child.stdin.end(
      JSON.stringify({
        ...request,
        keychain: options.keychain,
        interactive: options.interactive,
      }),
    );
  });
}

async function call(
  options: KeychainOptions,
  request: Record<string, unknown>,
  timeout: number,
): Promise<Record<string, unknown>> {
  const response = await run(options, request, timeout);
  if (response.ok === true) return response;
  const code = typeof response.code === "string" ? response.code : "";
  throw new CertificateError(
    messages[code] ?? "The Keychain could not complete the request.",
  );
}

function keychainProvider(
  options: KeychainOptions,
  certificates: Buffer[],
): CertificateProvider {
  const info = describeCertificate(certificates[0]);
  return {
    info,
    signer: certificates[0],
    certificates,
    async sign(data) {
      const { signature } = await call(
        options,
        {
          command: "sign",
          fingerprint: info.fingerprint,
          data: data.toString("base64"),
        },
        SIGN_TIMEOUT_MS,
      );
      if (typeof signature !== "string")
        throw new CertificateError("The Keychain helper failed.");
      return Buffer.from(signature, "base64");
    },
    // The Keychain holds the key. Nothing secret is kept here.
    clear() {},
  };
}

/**
 * Lists Keychain identities that can sign: an RSA private key and a
 * certificate within its validity dates. Signing uses the Keychain key through
 * the helper; macOS asks the user before each use it has not allowed.
 */
export async function listKeychainIdentities(
  options: KeychainOptions,
): Promise<CertificateProvider[]> {
  const { identities } = await call(
    options,
    { command: "list" },
    LIST_TIMEOUT_MS,
  );
  if (!Array.isArray(identities))
    throw new CertificateError("The Keychain helper failed.");
  return identities.flatMap((identity: { certificates?: unknown }) => {
    const encoded = identity?.certificates;
    if (!Array.isArray(encoded) || encoded.length === 0) return [];
    try {
      return [
        keychainProvider(
          options,
          encoded.map((der: string) => Buffer.from(der, "base64")),
        ),
      ];
    } catch {
      // Unreadable, expired, and not-yet-valid certificates are not eligible.
      return [];
    }
  });
}
