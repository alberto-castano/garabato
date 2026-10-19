import { randomUUID } from "node:crypto";
import type {
  CertificateInfo,
  DocumentInfo,
  KeychainIdentity,
} from "../shared/contracts";
import {
  type CertificateProvider,
  inspectPdf,
  openPkcs12,
  signPdf,
} from "./signing";

export class SigningSession {
  generation = 0;
  private pdf?: Buffer;
  /** A chosen certificate file that is not unlocked yet. */
  private p12?: Buffer;
  private provider?: CertificateProvider;
  /** The last Keychain listing, by opaque reference. */
  private keychain = new Map<string, CertificateProvider>();
  document?: DocumentInfo;

  assertActive(generation: number): void {
    if (generation !== this.generation)
      throw new Error("This session has closed. Choose your files again.");
  }

  async setDocument(
    name: string,
    bytes: Buffer,
    generation = this.generation,
  ): Promise<DocumentInfo> {
    let pageCount: number;
    try {
      this.assertActive(generation);
      ({ pageCount } = await inspectPdf(bytes));
      this.assertActive(generation);
    } catch (error) {
      bytes.fill(0);
      throw error;
    }
    this.pdf?.fill(0);
    this.pdf = bytes;
    this.document = { name, bytes: bytes.length, pageCount };
    return this.document;
  }

  setCertificate(bytes: Buffer, generation = this.generation): void {
    try {
      this.assertActive(generation);
    } catch (error) {
      bytes.fill(0);
      throw error;
    }
    this.clearCertificate();
    this.p12 = bytes;
  }

  unlock(password: unknown): CertificateInfo {
    // The file stays for another attempt; only the unlocked state is dropped.
    this.provider = undefined;
    if (typeof password !== "string" || password.length > 1024) {
      throw new Error(
        "Enter a certificate password of at most 1,024 characters.",
      );
    }
    if (!this.p12) throw new Error("Choose a certificate file first.");
    this.provider = openPkcs12(this.p12, password);
    return this.provider.info;
  }

  /**
   * Replaces the Keychain listing and returns opaque references to it.
   * A new listing starts a new certificate choice, so the current one is cleared.
   */
  setKeychainIdentities(
    providers: CertificateProvider[],
    generation = this.generation,
  ): KeychainIdentity[] {
    this.assertActive(generation);
    this.clearCertificate();
    this.keychain = new Map(
      providers.map((provider) => [randomUUID(), provider]),
    );
    return [...this.keychain].map(([id, { info }]) => ({ id, ...info }));
  }

  selectKeychainIdentity(id: unknown): CertificateInfo {
    const provider = typeof id === "string" ? this.keychain.get(id) : undefined;
    if (!provider) throw new Error("Find your Keychain certificates again.");
    this.clearCertificate();
    this.provider = provider;
    return provider.info;
  }

  async sign(): Promise<Buffer> {
    if (!this.pdf || !this.provider) {
      throw new Error("Choose a PDF and a certificate first.");
    }
    return signPdf(this.pdf, this.provider);
  }

  clearCertificate(): void {
    this.provider?.clear();
    this.provider = undefined;
    this.p12?.fill(0);
    this.p12 = undefined;
  }

  reset(): void {
    this.generation += 1;
    this.clearCertificate();
    this.keychain.clear();
    this.pdf?.fill(0);
    this.pdf = undefined;
    this.document = undefined;
  }
}
