// RC2 decryption (RFC 2268) for legacy PKCS#12 containers. Node's OpenSSL 3
// build omits RC2 from its default provider, so Garabato implements it here.

// RFC 2268 section 2: PITABLE, a permutation of 0..255 derived from pi.
const piTable = Buffer.from(
  "d978f9c419ddb5ed28e9fd794aa0d89dc67e37832b76538e624c6488448bfba2" +
    "179a59f587b34f1361456d8d09817d32bd8f40eb86b77b0bf09521225c6b4e82" +
    "54d66593ce60b21c7356c014a78cf1dc1275ca1f3bbee4d1423dd430a33cb626" +
    "6fbf0eda4669075727f21d9bbc944303f811c7f690ef3ee706c3d52fc8661ed7" +
    "08e8eade8052eef784aa72ac354d6a2a961ad2715a1549744b9fd05e0418a4ec" +
    "c2e0416e0f51cbcc2491af50a1f47039997c3a8523b8b47afc02365b25559731" +
    "2d5dfa98e38a92ae05df2910676cbac9d300e6cfe19ea82c6316013f58e289a9" +
    "0d38341bab33ffb0bb480c5fb9b1cd2ec5f3db47e5a59c770aa62068fe7fc1ad",
  "hex",
);

function expandKey(key: Buffer, effectiveBits: number): Uint16Array {
  const bytes = Buffer.alloc(128);
  key.copy(bytes);
  for (let i = key.length; i < 128; i += 1) {
    bytes[i] = piTable[(bytes[i - 1] + bytes[i - key.length]) & 0xff];
  }
  const t8 = Math.ceil(effectiveBits / 8);
  const tm = 0xff >> (8 * t8 - effectiveBits);
  bytes[128 - t8] = piTable[bytes[128 - t8] & tm];
  for (let i = 127 - t8; i >= 0; i -= 1) {
    bytes[i] = piTable[bytes[i + 1] ^ bytes[i + t8]];
  }
  const words = new Uint16Array(64);
  for (let i = 0; i < 64; i += 1) words[i] = bytes.readUInt16LE(i * 2);
  return words;
}

const shifts = [1, 2, 3, 5];

function decryptBlock(k: Uint16Array, block: Buffer): Buffer {
  const r = [0, 1, 2, 3].map((i) => block.readUInt16LE(i * 2));
  let j = 63;
  const mix = () => {
    for (let i = 3; i >= 0; i -= 1) {
      const x = r[i];
      r[i] = ((x >>> shifts[i]) | (x << (16 - shifts[i]))) & 0xffff;
      r[i] =
        (r[i] -
          k[j] -
          (r[(i + 3) % 4] & r[(i + 2) % 4]) -
          (~r[(i + 3) % 4] & r[(i + 1) % 4])) &
        0xffff;
      j -= 1;
    }
  };
  const mash = () => {
    for (let i = 3; i >= 0; i -= 1) {
      r[i] = (r[i] - k[r[(i + 3) % 4] & 63]) & 0xffff;
    }
  };
  // RFC 2268 section 4: the encryption rounds in reverse order.
  for (const step of [5, 0, 6, 0, 5]) {
    if (step === 0) mash();
    else for (let n = 0; n < step; n += 1) mix();
  }
  const output = Buffer.alloc(8);
  r.forEach((word, i) => {
    output.writeUInt16LE(word, i * 2);
  });
  return output;
}

/** Decrypts RC2-CBC data and removes PKCS#7 padding. */
export function rc2DecryptCbc(
  key: Buffer,
  effectiveBits: number,
  iv: Buffer,
  data: Buffer,
): Buffer {
  if (data.length === 0 || data.length % 8 !== 0 || iv.length !== 8) {
    throw new Error("Invalid RC2 input");
  }
  const k = expandKey(key, effectiveBits);
  const output = Buffer.alloc(data.length);
  let previous = iv;
  for (let offset = 0; offset < data.length; offset += 8) {
    const block = data.subarray(offset, offset + 8);
    const plain = decryptBlock(k, block);
    for (let i = 0; i < 8; i += 1) output[offset + i] = plain[i] ^ previous[i];
    previous = block;
  }
  const padding = output[output.length - 1];
  if (
    padding < 1 ||
    padding > 8 ||
    !output.subarray(output.length - padding).every((byte) => byte === padding)
  ) {
    throw new Error("Invalid RC2 padding");
  }
  return output.subarray(0, output.length - padding);
}
