import { type ReactNode, useEffect, useRef, useState } from "react";
import type { PDFDocumentProxy } from "@/lib/pdf";

export interface PageSize {
  /** Displayed size in PDF points, after page rotation. */
  width: number;
  height: number;
}

/** Renders one page at the given zoom, with an overlay of the same size. */
export function PdfPage({
  pdf,
  page,
  zoom,
  label,
  onSize,
  children,
}: {
  pdf: PDFDocumentProxy;
  /** Zero-based page index. */
  page: number;
  zoom: number;
  label: string;
  onSize?(size: PageSize): void;
  /** An overlay with the page's displayed size. */
  children?: ReactNode;
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const [size, setSize] = useState<PageSize | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let task: ReturnType<
      Awaited<ReturnType<PDFDocumentProxy["getPage"]>>["render"]
    > | null = null;
    setFailed(false);
    void (async () => {
      try {
        const proxy = await pdf.getPage(page + 1);
        if (cancelled || !canvas.current) return;
        const { width, height } = proxy.getViewport({ scale: 1 });
        const ratio = window.devicePixelRatio || 1;
        const viewport = proxy.getViewport({ scale: zoom * ratio });
        canvas.current.width = Math.floor(viewport.width);
        canvas.current.height = Math.floor(viewport.height);
        setSize({ width, height });
        onSize?.({ width, height });
        task = proxy.render({ canvas: canvas.current, viewport });
        await task.promise;
      } catch (error) {
        if (
          !cancelled &&
          (error as Error)?.name !== "RenderingCancelledException"
        )
          setFailed(true);
      }
    })();
    return () => {
      cancelled = true;
      task?.cancel();
    };
  }, [pdf, page, zoom, onSize]);

  return (
    <div
      className="relative mx-auto bg-white shadow-sm"
      style={
        size
          ? { width: size.width * zoom, height: size.height * zoom }
          : undefined
      }
    >
      <canvas
        ref={canvas}
        role="img"
        aria-label={label}
        className="block size-full"
      />
      {failed && (
        <p className="absolute inset-0 grid place-items-center p-6 text-center text-sm text-muted-foreground">
          This page cannot be previewed. You can still sign without a visible
          box.
        </p>
      )}
      {size && children}
    </div>
  );
}
