import {
  GlobalWorkerOptions,
  getDocument,
  type PDFDocumentProxy,
} from "pdfjs-dist";
import workerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";

export type { PDFDocumentProxy } from "pdfjs-dist";

// The worker is a bundled file, so preview never fetches remote code.
GlobalWorkerOptions.workerSrc = workerUrl;

/** Parses a PDF for preview. The bytes never leave this process. */
export function openPdf(data: Uint8Array): Promise<PDFDocumentProxy> {
  return getDocument({
    // pdf.js transfers the buffer to its worker, so give it a copy.
    data: data.slice(),
    // The CSP blocks WebAssembly; JavaScript decoders render the same images.
    useWasm: false,
    enableXfa: false,
  }).promise;
}
