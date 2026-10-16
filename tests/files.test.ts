import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { readBoundedFile, saveNewFile } from "../src/main/files";

let folder: string;
beforeEach(async () => {
  folder = await mkdtemp(join(tmpdir(), "garabato-files-"));
});
afterEach(async () => {
  await rm(folder, { recursive: true, force: true });
});

it("saves a new copy but never overwrites an existing file", async () => {
  const path = join(folder, "copy.pdf");
  await saveNewFile(path, Buffer.from("first copy"));
  await expect(saveNewFile(path, Buffer.from("replacement"))).rejects.toThrow();
  expect((await readFile(path)).toString()).toBe("first copy");
});

it("limits reads and rejects empty files and directories", async () => {
  const path = join(folder, "input.pdf");
  await writeFile(path, "12345");
  await expect(readBoundedFile(path, 4)).rejects.toThrow("size limit");
  expect((await readBoundedFile(path, 5)).toString()).toBe("12345");
  await writeFile(path, "");
  await expect(readBoundedFile(path, 5)).rejects.toThrow();
  await expect(readBoundedFile(folder, 5)).rejects.toThrow();
});
