import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": resolve("src/renderer/src") } },
  test: { include: ["tests/**/*.test.{ts,tsx}"], testTimeout: 30_000 },
});
