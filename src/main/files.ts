import { open, unlink } from "node:fs/promises";

export async function readBoundedFile(
  path: string,
  limit: number,
): Promise<Buffer> {
  const file = await open(path, "r");
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size === 0 || info.size > limit) {
      throw new Error("Choose a non-empty file within the size limit.");
    }
    // Read at most limit + 1 even if another process grows the file after stat.
    const chunks: Buffer[] = [];
    let total = 0;
    while (total <= limit) {
      const buffer = Buffer.alloc(Math.min(64 * 1024, limit + 1 - total));
      const { bytesRead } = await file.read(buffer);
      if (bytesRead === 0) break;
      chunks.push(buffer.subarray(0, bytesRead));
      total += bytesRead;
    }
    if (total > limit) throw new Error("The file exceeds the size limit.");
    return Buffer.concat(chunks);
  } finally {
    await file.close();
  }
}

export async function saveNewFile(path: string, bytes: Buffer): Promise<void> {
  // Never overwrite the source, a certificate, or any existing destination.
  const file = await open(path, "wx", 0o600);
  try {
    await file.writeFile(bytes);
    await file.sync();
  } catch (error) {
    await file.close();
    await unlink(path).catch(() => undefined);
    throw error;
  }
  await file.close();
}
