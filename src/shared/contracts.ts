export type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export interface DocumentInfo {
  name: string;
  bytes: number;
  pageCount: number;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  fingerprint: string;
}

export interface SignedFile {
  name: string;
  bytes: number;
}

export interface GarabatoApi {
  choosePdf(): Promise<Result<DocumentInfo | null>>;
  chooseCertificate(): Promise<Result<{ name: string } | null>>;
  unlockCertificate(password: string): Promise<Result<CertificateInfo>>;
  signAndSave(): Promise<Result<SignedFile | null>>;
  reset(): Promise<Result<null>>;
}
