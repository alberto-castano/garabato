export type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export interface DocumentInfo {
  name: string;
  bytes: number;
  pageCount: number;
}

/** A copy of the chosen PDF for local preview in the renderer. */
export interface OpenedDocument extends DocumentInfo {
  data: Uint8Array;
}

/**
 * The visible signature box on a page as the reader displays it, after page
 * rotation. Values are fractions of the displayed page, from its top-left corner.
 */
export interface Placement {
  /** Zero-based page index. */
  page: number;
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Smallest signature box, in PDF points, that keeps its text readable. */
export const MIN_BOX_WIDTH = 72;
export const MIN_BOX_HEIGHT = 24;

export interface CertificateInfo {
  subject: string;
  /** Subject common name, or the full subject if it has none. */
  signer: string;
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
  choosePdf(): Promise<Result<OpenedDocument | null>>;
  chooseCertificate(): Promise<Result<{ name: string } | null>>;
  unlockCertificate(password: string): Promise<Result<CertificateInfo>>;
  /** An unsigned copy with the signature box drawn, for the final preview. */
  previewSignature(placement: Placement): Promise<Result<Uint8Array>>;
  /** Without a placement, the signature has no visible box. */
  signAndSave(placement: Placement | null): Promise<Result<SignedFile | null>>;
  reset(): Promise<Result<null>>;
}
