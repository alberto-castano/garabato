import {
  ChevronLeftIcon,
  ChevronRightIcon,
  SquareDashedIcon,
  Trash2Icon,
  ZoomInIcon,
  ZoomOutIcon,
} from "lucide-react";
import {
  type KeyboardEvent,
  type PointerEvent,
  type Ref,
  useRef,
  useState,
} from "react";
import { flushSync } from "react-dom";
import { Button } from "@/components/ui/button";
import type { PDFDocumentProxy } from "@/lib/pdf";
import {
  MIN_BOX_HEIGHT,
  MIN_BOX_WIDTH,
  type Placement,
} from "../../../shared/contracts";
import { type PageSize, PdfPage } from "./pdf-page";

const ZOOM_LEVELS = [0.5, 0.75, 1, 1.25, 1.5, 2];
// A typical stamp: room for three lines of 10-point text.
const DEFAULT_BOX = { width: 180, height: 54 };
const KEY_STEP = 0.01;

type Box = Omit<Placement, "page">;

/** Keeps a box inside the page and no smaller than the readable minimum. */
function clampBox(box: Box, size: PageSize): Box {
  const width = Math.min(1, Math.max(MIN_BOX_WIDTH / size.width, box.width));
  const height = Math.min(
    1,
    Math.max(MIN_BOX_HEIGHT / size.height, box.height),
  );
  return {
    x: Math.min(1 - width, Math.max(0, box.x)),
    y: Math.min(1 - height, Math.max(0, box.y)),
    width,
    height,
  };
}

function defaultBox(size: PageSize, center?: { x: number; y: number }): Box {
  const width = DEFAULT_BOX.width / size.width;
  const height = DEFAULT_BOX.height / size.height;
  // Without a center, use the lower-right corner, where signatures usually go.
  const x = center ? center.x - width / 2 : 0.94 - width;
  const y = center ? center.y - height / 2 : 0.92 - height;
  return clampBox({ x, y, width, height }, size);
}

function percent(value: number) {
  return `${Math.round(value * 100)}%`;
}

function PlacementLayer({
  size,
  page,
  placement,
  disabled,
  boxRef,
  onChange,
  onRemove,
}: {
  size: PageSize;
  page: number;
  placement: Placement | null;
  disabled: boolean;
  boxRef: Ref<HTMLButtonElement>;
  onChange(placement: Placement): void;
  onRemove(): void;
}) {
  const layer = useRef<HTMLDivElement>(null);
  const drag = useRef<{
    mode: "draw" | "move" | "resize";
    start: { x: number; y: number };
    origin: Box;
  } | null>(null);
  const box = placement?.page === page ? placement : null;

  function point(event: PointerEvent) {
    const bounds = layer.current?.getBoundingClientRect();
    if (!bounds?.width || !bounds.height) return { x: 0, y: 0 };
    return {
      x: (event.clientX - bounds.left) / bounds.width,
      y: (event.clientY - bounds.top) / bounds.height,
    };
  }

  function update(next: Box) {
    onChange({ page, ...clampBox(next, size) });
  }

  function pointerDown(event: PointerEvent<HTMLDivElement>) {
    if (disabled || event.button !== 0) return;
    const target = event.target as HTMLElement;
    const mode =
      box && target.closest("[data-resize]")
        ? "resize"
        : box && target.closest("[data-box]")
          ? "move"
          : "draw";
    const start = point(event);
    drag.current = {
      mode,
      start,
      origin:
        mode === "draw"
          ? { ...start, width: 0, height: 0 }
          : (box ?? defaultBox(size)),
    };
    event.currentTarget.setPointerCapture?.(event.pointerId);
    event.preventDefault();
  }

  function pointerMove(event: PointerEvent<HTMLDivElement>) {
    const current = drag.current;
    if (!current) return;
    const now = point(event);
    const across = now.x - current.start.x;
    const down = now.y - current.start.y;
    const { origin } = current;
    if (current.mode === "move") {
      update({ ...origin, x: origin.x + across, y: origin.y + down });
    } else if (current.mode === "resize") {
      update({
        ...origin,
        width: origin.width + across,
        height: origin.height + down,
      });
    } else {
      update({
        x: Math.min(current.start.x, now.x),
        y: Math.min(current.start.y, now.y),
        width: Math.abs(across),
        height: Math.abs(down),
      });
    }
  }

  function pointerUp(event: PointerEvent<HTMLDivElement>) {
    const current = drag.current;
    drag.current = null;
    if (current?.mode !== "draw") return;
    const now = point(event);
    // A click, not a drag: put a box of the usual size there.
    if (
      Math.abs(now.x - current.start.x) * size.width < MIN_BOX_WIDTH &&
      Math.abs(now.y - current.start.y) * size.height < MIN_BOX_HEIGHT
    ) {
      update(defaultBox(size, current.start));
    }
  }

  function keyDown(event: KeyboardEvent<HTMLButtonElement>) {
    if (!box || disabled) return;
    const step = event.altKey ? KEY_STEP / 5 : KEY_STEP;
    const moves: Record<string, Partial<Box>> = event.shiftKey
      ? {
          ArrowLeft: { width: box.width - step },
          ArrowRight: { width: box.width + step },
          ArrowUp: { height: box.height - step },
          ArrowDown: { height: box.height + step },
        }
      : {
          ArrowLeft: { x: box.x - step },
          ArrowRight: { x: box.x + step },
          ArrowUp: { y: box.y - step },
          ArrowDown: { y: box.y + step },
        };
    if (event.key in moves) {
      event.preventDefault();
      update({ ...box, ...moves[event.key] });
    } else if (["Delete", "Backspace", "Escape"].includes(event.key)) {
      event.preventDefault();
      onRemove();
    }
  }

  return (
    // Pointer drawing is a shortcut; the toolbar and keys do the same.
    <div
      ref={layer}
      className={
        disabled
          ? "absolute inset-0"
          : "absolute inset-0 cursor-crosshair touch-none"
      }
      onPointerDown={pointerDown}
      onPointerMove={pointerMove}
      onPointerUp={pointerUp}
      onPointerCancel={() => {
        drag.current = null;
      }}
    >
      {box && (
        <button
          ref={boxRef}
          type="button"
          data-box
          disabled={disabled}
          aria-label={`Signature box on page ${page + 1}`}
          aria-describedby="box-help"
          onKeyDown={keyDown}
          className="absolute flex cursor-move items-center justify-center border-2 border-primary bg-primary/10 text-xs font-medium text-primary outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
          style={{
            left: percent(box.x),
            top: percent(box.y),
            width: percent(box.width),
            height: percent(box.height),
          }}
        >
          Signature
          <span
            data-resize
            aria-hidden="true"
            className="absolute -right-1.5 -bottom-1.5 size-3 cursor-nwse-resize rounded-sm border-2 border-background bg-primary"
          />
        </button>
      )}
    </div>
  );
}

export function DocumentPreview({
  pdf,
  pageCount,
  placement,
  disabled,
  onPlacementChange,
}: {
  pdf: PDFDocumentProxy;
  pageCount: number;
  placement: Placement | null;
  disabled: boolean;
  onPlacementChange(placement: Placement | null): void;
}) {
  const [page, setPage] = useState(0);
  const [zoomIndex, setZoomIndex] = useState(1);
  const [size, setSize] = useState<PageSize | null>(null);
  const box = useRef<HTMLButtonElement>(null);
  const addButton = useRef<HTMLButtonElement>(null);
  const onThisPage = placement?.page === page;

  function addBox() {
    if (!size) return;
    flushSync(() => onPlacementChange({ page, ...defaultBox(size) }));
    box.current?.focus();
  }

  function removeBox() {
    flushSync(() => onPlacementChange(null));
    addButton.current?.focus();
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Previous page"
            disabled={page === 0}
            onClick={() => setPage(page - 1)}
          >
            <ChevronLeftIcon />
          </Button>
          <span className="min-w-24 text-center text-sm tabular-nums">
            Page {page + 1} of {pageCount}
          </span>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Next page"
            disabled={page >= pageCount - 1}
            onClick={() => setPage(page + 1)}
          >
            <ChevronRightIcon />
          </Button>
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Zoom out"
            disabled={zoomIndex === 0}
            onClick={() => setZoomIndex(zoomIndex - 1)}
          >
            <ZoomOutIcon />
          </Button>
          <output
            aria-label="Zoom level"
            className="min-w-12 text-center text-sm tabular-nums"
          >
            {percent(ZOOM_LEVELS[zoomIndex])}
          </output>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Zoom in"
            disabled={zoomIndex === ZOOM_LEVELS.length - 1}
            onClick={() => setZoomIndex(zoomIndex + 1)}
          >
            <ZoomInIcon />
          </Button>
        </div>
      </div>

      <div className="max-h-[560px] overflow-auto rounded-lg border bg-muted p-4">
        <PdfPage
          pdf={pdf}
          page={page}
          zoom={ZOOM_LEVELS[zoomIndex]}
          label={`Page ${page + 1} of ${pageCount}`}
          onSize={setSize}
        >
          {size && (
            <PlacementLayer
              size={size}
              page={page}
              placement={placement}
              disabled={disabled}
              boxRef={box}
              onChange={onPlacementChange}
              onRemove={removeBox}
            />
          )}
        </PdfPage>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button
          ref={addButton}
          variant="outline"
          size="sm"
          disabled={disabled || !size || onThisPage}
          onClick={addBox}
        >
          <SquareDashedIcon data-icon="inline-start" />
          {placement ? "Move box to this page" : "Add signature box"}
        </Button>
        {placement && (
          <Button
            variant="ghost"
            size="sm"
            disabled={disabled}
            onClick={removeBox}
          >
            <Trash2Icon data-icon="inline-start" /> Remove box
          </Button>
        )}
      </div>
      <p id="box-help" className="text-sm text-muted-foreground">
        Drag on the page to draw a visible signature box. To move the selected
        box, use the arrow keys. To resize it, hold Shift. To remove it, press
        Delete or Escape.
      </p>
      <p aria-live="polite" className="text-sm">
        {placement && size && onThisPage
          ? `Box on page ${placement.page + 1}, ${percent(placement.x)} from the left and ${percent(placement.y)} from the top, ${Math.round(placement.width * size.width)} × ${Math.round(placement.height * size.height)} points.`
          : placement
            ? `Box on page ${placement.page + 1}.`
            : "No visible box. The signature will be invisible."}
      </p>
    </div>
  );
}
