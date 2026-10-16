import { describe, expect, it } from "vitest";
import { pkcs12Kdf } from "../src/main/pkcs12";
import { rc2DecryptCbc } from "../src/main/rc2";

describe("PKCS#12 primitives", () => {
  // Published SHA-1 vectors from the Bouncy Castle PKCS#12 test suite.
  it.each([
    [
      "smeg",
      "0a58cf64530d823f",
      1,
      1,
      "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3",
    ],
    ["smeg", "0a58cf64530d823f", 2, 1, "79993dfe048d3b76"],
    [
      "smeg",
      "3d83c0e4546ac140",
      3,
      1,
      "8d967d88f6caa9d714800ab3d48051d63f73a312",
    ],
    [
      "queeg",
      "05dec959acff72f7",
      1,
      1000,
      "ed2034e36328830ff09df1e1a07dd357185dac0d4f9eb3d4",
    ],
    ["queeg", "05dec959acff72f7", 2, 1000, "11dedad7758d4860"],
  ] as const)(
    "derives the RFC 7292 key for %s, salt %s, ID %i",
    (password, salt, id, count, expected) => {
      expect(
        pkcs12Kdf(
          "sha1",
          password,
          Buffer.from(salt, "hex"),
          id,
          count,
          expected.length / 2,
        ).toString("hex"),
      ).toBe(expected);
    },
  );

  // Ciphertexts from `openssl enc -rc2-40-cbc` and `-rc2-cbc` with the legacy provider.
  it.each([
    [
      "0102030405",
      40,
      "3ed5a2434cf117f4b4a141153a14ffe2dc619a718945e2a129f951ad27eb34c9",
    ],
    [
      "88bca90e90875a7f0f79c384627bafb2",
      128,
      "4aa89037b414b76d0e1aefdf2f2c3c7af0cfb05465d9998bc99dfbc83d703569",
    ],
  ] as const)(
    "decrypts RC2-CBC with key %s and %i effective bits",
    (key, bits, ciphertext) => {
      expect(
        rc2DecryptCbc(
          Buffer.from(key, "hex"),
          bits,
          Buffer.from("0011223344556677", "hex"),
          Buffer.from(ciphertext, "hex"),
        ).toString(),
      ).toBe("Garabato RC2 vector, 3 blocks!");
    },
  );

  it("rejects RC2 data with invalid padding", () => {
    expect(() =>
      rc2DecryptCbc(Buffer.alloc(5, 1), 40, Buffer.alloc(8), Buffer.alloc(16)),
    ).toThrow("padding");
  });
});
