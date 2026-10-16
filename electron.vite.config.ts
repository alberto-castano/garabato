import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "electron-vite";

export default defineConfig(({ command }) => {
  const nonce =
    command === "serve" ? randomBytes(18).toString("base64") : undefined;
  return {
    main: {},
    preload: {
      build: {
        rolldownOptions: {
          output: { format: "cjs", entryFileNames: "index.cjs" },
        },
      },
    },
    renderer: {
      html: { cspNonce: nonce },
      resolve: { alias: { "@": resolve("src/renderer/src") } },
      plugins: [
        react(),
        tailwindcss(),
        {
          name: "garabato-csp",
          transformIndexHtml(html) {
            // Vite's React refresh preamble needs a nonce during development only.
            return nonce
              ? html.replace(
                  "script-src 'self'",
                  `script-src 'self' 'nonce-${nonce}'`,
                )
              : html.replace(
                  "connect-src 'self' ws://localhost:* ws://127.0.0.1:*",
                  "connect-src 'none'",
                );
          },
        },
      ],
    },
  };
});
