import type { CertificateInfo, DocumentInfo } from "../shared/contracts";
import {
  inspectCertificate,
  inspectPdf,
  parsePlacement,
  previewBox,
  signPdf,
} from "./signing";

export class SigningSession {
  generation = 0;
  private pdf?: Buffer;
  private p12?: Buffer;
  private password?: string;
  private certificate?: CertificateInfo;
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
    this.password = undefined;
    this.certificate = undefined;
    if (typeof password !== "string" || password.length > 1024) {
      throw new Error(
        "Enter a certificate password of at most 1,024 characters.",
      );
    }
    if (!this.p12) throw new Error("Choose a certificate file first.");
    const certificate = inspectCertificate(this.p12, password);
    this.password = password;
    this.certificate = certificate;
    return certificate;
  }

  async preview(placement: unknown): Promise<Buffer> {
    const box = parsePlacement(placement);
    if (!this.pdf || !this.certificate) {
      throw new Error("Choose a PDF and unlock your certificate first.");
    }
    if (!box) throw new Error("Place the signature box first.");
    return previewBox(this.pdf, box, this.certificate.signer);
  }

  async sign(placement: unknown = null): Promise<Buffer> {
    const box = parsePlacement(placement);
    if (!this.pdf || !this.p12 || this.password === undefined) {
      throw new Error("Choose a PDF and unlock your certificate first.");
    }
    return signPdf(this.pdf, this.p12, this.password, box);
  }

  clearCertificate(): void {
    this.p12?.fill(0);
    this.p12 = undefined;
    this.password = undefined;
    this.certificate = undefined;
  }

  reset(): void {
    this.generation += 1;
    this.clearCertificate();
    this.pdf?.fill(0);
    this.pdf = undefined;
    this.document = undefined;
  }
}
