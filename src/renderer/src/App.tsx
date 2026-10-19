import {
  ArrowRightIcon,
  CheckIcon,
  FileCheck2Icon,
  FileTextIcon,
  FolderOpenIcon,
  KeyRoundIcon,
  LockKeyholeIcon,
  PenLineIcon,
  ShieldCheckIcon,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { DocumentPreview } from "@/components/document-preview";
import { SignatureReview } from "@/components/signature-review";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { openPdf, type PDFDocumentProxy } from "@/lib/pdf";
import type {
  CertificateInfo,
  DocumentInfo,
  GarabatoApi,
  Placement,
  Result,
  SignedFile,
} from "../../shared/contracts";

function unwrap<T>(result: Result<T>): T {
  if (!result.ok) throw new Error(result.error);
  return result.value;
}

function formatBytes(bytes: number) {
  return bytes < 1024 * 1024
    ? `${Math.ceil(bytes / 1024)} KB`
    : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function App({ api = window.garabato }: { api?: GarabatoApi }) {
  const [document, setDocument] = useState<DocumentInfo | null>(null);
  const [certificateFile, setCertificateFile] = useState<string | null>(null);
  const [certificate, setCertificate] = useState<CertificateInfo | null>(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState<string | null>(null);
  const [saved, setSaved] = useState<SignedFile | null>(null);
  const [pdf, setPdf] = useState<PDFDocumentProxy | null>(null);
  // A new key resets page and zoom when another PDF opens.
  const [pdfKey, setPdfKey] = useState(0);
  const [placement, setPlacement] = useState<Placement | null>(null);
  const [review, setReview] = useState<{
    preview: PDFDocumentProxy | null;
  } | null>(null);
  const inFlight = useRef(false);
  const disabled = Boolean(working) || !api;

  useEffect(
    () => () => {
      void pdf?.loadingTask.destroy();
    },
    [pdf],
  );
  useEffect(
    () => () => {
      void review?.preview?.loadingTask.destroy();
    },
    [review],
  );

  async function run(label: string, operation: () => Promise<void>) {
    if (inFlight.current) return;
    inFlight.current = true;
    setWorking(label);
    setError(null);
    try {
      await operation();
    } catch (failure) {
      setError(
        failure instanceof Error
          ? failure.message
          : "The operation failed. Please try again.",
      );
    } finally {
      setWorking(null);
      inFlight.current = false;
    }
  }

  function choosePdf() {
    if (!api) return;
    void run("Reading PDF…", async () => {
      const chosen = unwrap(await api.choosePdf());
      if (chosen) {
        const { data, ...info } = chosen;
        // Signing does not need the preview, so a pdf.js failure is not fatal.
        const opened = await openPdf(data).catch(() => null);
        setDocument(info);
        setPdf(opened);
        setPdfKey((key) => key + 1);
        setPlacement(null);
        setSaved(null);
      }
    });
  }

  function chooseCertificate() {
    if (!api) return;
    void run("Opening certificate…", async () => {
      const chosen = unwrap(await api.chooseCertificate());
      if (chosen) {
        setCertificateFile(chosen.name);
        setCertificate(null);
        setPassword("");
        setSaved(null);
      }
    });
  }

  function unlock() {
    if (!api) return;
    void run("Reading certificate…", async () => {
      setCertificate(null);
      try {
        setCertificate(unwrap(await api.unlockCertificate(password)));
      } finally {
        setPassword("");
      }
    });
  }

  function startReview() {
    if (!api) return;
    void run("Preparing the final preview…", async () => {
      const preview = placement
        ? await openPdf(unwrap(await api.previewSignature(placement))).catch(
            () => null,
          )
        : null;
      setReview({ preview });
    });
  }

  function sign() {
    if (!api) return;
    void run("Signing and saving…", async () => {
      const result = unwrap(await api.signAndSave(placement));
      if (result) {
        setReview(null);
        setSaved(result);
        setCertificate(null);
        setCertificateFile(null);
        setPassword("");
      }
    });
  }

  function reset() {
    if (!api) return;
    void run("Clearing session…", async () => {
      unwrap(await api.reset());
      setReview(null);
      setPlacement(null);
      setPdf(null);
      setDocument(null);
      setCertificate(null);
      setCertificateFile(null);
      setPassword("");
      setSaved(null);
    });
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-6xl flex-col px-6 sm:px-10">
      <header className="flex items-center justify-between gap-4 border-b py-7">
        <div className="flex items-center gap-3">
          <PenLineIcon className="size-6 text-primary" aria-hidden="true" />
          <span className="wordmark text-3xl">garabato</span>
        </div>
        <Badge variant="secondary">
          <LockKeyholeIcon data-icon="inline-start" /> Local signing
        </Badge>
      </header>

      <main className="flex flex-1 flex-col gap-7 py-10">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="flex flex-col gap-3">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              A signature. A few simple steps.
            </p>
            <h1 className="text-4xl font-medium tracking-tight">
              Make it official.
            </h1>
            <p className="max-w-lg text-base text-muted-foreground">
              Sign a PDF with your digital certificate. Your document stays on
              this computer.
            </p>
          </div>
          <Button
            variant="ghost"
            disabled={disabled || (!document && !certificateFile)}
            onClick={reset}
          >
            Clear session
          </Button>
        </div>

        {!api && (
          <Alert>
            <AlertTitle>Open the desktop app to sign</AlertTitle>
            <AlertDescription>
              This browser view cannot access your documents or certificates.
              Start Garabato with <code>bun run dev</code>.
            </AlertDescription>
          </Alert>
        )}
        {error && (
          <Alert variant="destructive">
            <AlertTitle>Could not complete this step</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {saved ? (
          <Card>
            <CardHeader>
              <CardTitle>Signed copy saved</CardTitle>
              <CardDescription>Your original PDF is unchanged.</CardDescription>
            </CardHeader>
            <CardContent>
              <Empty>
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <FileCheck2Icon />
                  </EmptyMedia>
                  <EmptyTitle>{saved.name}</EmptyTitle>
                  <EmptyDescription>
                    {formatBytes(saved.bytes)} · Digital signature added. Your
                    certificate has been cleared from the session.
                  </EmptyDescription>
                </EmptyHeader>
                <EmptyContent>
                  <Button onClick={reset} disabled={disabled}>
                    Sign another document{" "}
                    <ArrowRightIcon data-icon="inline-end" />
                  </Button>
                </EmptyContent>
              </Empty>
            </CardContent>
            <CardFooter>
              <p className="text-sm text-muted-foreground">
                Certificate trust and revocation have not been checked. Open the
                copy in your PDF reader to inspect its signature.
              </p>
            </CardFooter>
          </Card>
        ) : review && certificate ? (
          <SignatureReview
            preview={review.preview}
            placement={placement}
            certificate={certificate}
            disabled={disabled}
            onBack={() => setReview(null)}
            onSign={sign}
          />
        ) : (
          <div className="grid items-start gap-5 lg:grid-cols-[1.1fr_1fr]">
            <Card>
              <CardHeader>
                <CardTitle>
                  <h2>01 / Your document</h2>
                </CardTitle>
                <CardDescription>
                  One unsigned PDF, up to 25 MiB.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {document ? (
                  <div className="flex flex-col gap-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex min-w-0 flex-col gap-1">
                        <p className="break-all font-medium">{document.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {document.pageCount}{" "}
                          {document.pageCount === 1 ? "page" : "pages"} ·{" "}
                          {formatBytes(document.bytes)}
                        </p>
                      </div>
                      <Button
                        variant="outline"
                        onClick={choosePdf}
                        disabled={disabled}
                      >
                        <FolderOpenIcon data-icon="inline-start" />
                        Change PDF
                      </Button>
                    </div>
                    {pdf ? (
                      <DocumentPreview
                        key={pdfKey}
                        pdf={pdf}
                        pageCount={document.pageCount}
                        placement={placement}
                        disabled={disabled}
                        onPlacementChange={setPlacement}
                      />
                    ) : (
                      <Alert>
                        <AlertTitle>Preview is not available</AlertTitle>
                        <AlertDescription>
                          This PDF cannot be shown here. You can still sign it
                          without a visible box.
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                ) : (
                  <Empty className="min-h-64 border">
                    <EmptyHeader>
                      <EmptyMedia variant="icon">
                        <FileTextIcon />
                      </EmptyMedia>
                      <EmptyTitle>Start with a PDF</EmptyTitle>
                      <EmptyDescription>
                        Choose the document you want to sign. We’ll save a
                        separate signed copy.
                      </EmptyDescription>
                    </EmptyHeader>
                    <EmptyContent>
                      <Button onClick={choosePdf} disabled={disabled}>
                        <FolderOpenIcon data-icon="inline-start" />
                        Choose PDF
                      </Button>
                    </EmptyContent>
                  </Empty>
                )}
              </CardContent>
              <CardFooter>
                <p className="text-sm text-muted-foreground">
                  Encrypted PDFs, XFA forms, and documents with existing
                  signatures are not supported yet.
                </p>
              </CardFooter>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>
                  <h2>02 / Your certificate</h2>
                </CardTitle>
                <CardDescription>
                  Use an RSA certificate in a .p12 or .pfx file.
                </CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-5">
                <Button
                  variant="outline"
                  onClick={chooseCertificate}
                  disabled={disabled}
                >
                  <KeyRoundIcon data-icon="inline-start" />
                  {certificateFile
                    ? "Change certificate"
                    : "Choose certificate"}
                </Button>
                {certificateFile && (
                  <p className="break-all text-sm text-muted-foreground">
                    {certificateFile}
                  </p>
                )}
                {certificate ? (
                  <div className="flex flex-col gap-4">
                    <Badge variant="secondary">
                      <CheckIcon data-icon="inline-start" /> Certificate
                      unlocked
                    </Badge>
                    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-3 text-sm">
                      <dt className="text-muted-foreground">Signed by</dt>
                      <dd className="break-words font-medium">
                        {certificate.subject}
                      </dd>
                      <dt className="text-muted-foreground">Issuer</dt>
                      <dd className="break-words">{certificate.issuer}</dd>
                      <dt className="text-muted-foreground">Expires</dt>
                      <dd>
                        {new Date(certificate.validTo).toLocaleDateString()}
                      </dd>
                    </dl>
                    <p className="break-all font-mono text-xs text-muted-foreground">
                      SHA-256 · {certificate.fingerprint}
                    </p>
                  </div>
                ) : certificateFile ? (
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      unlock();
                    }}
                  >
                    <FieldGroup>
                      <Field data-disabled={disabled}>
                        <FieldLabel htmlFor="password">
                          Certificate password
                        </FieldLabel>
                        <Input
                          id="password"
                          type="password"
                          value={password}
                          maxLength={1024}
                          autoComplete="off"
                          spellCheck={false}
                          disabled={disabled}
                          onChange={(event) => setPassword(event.target.value)}
                          aria-describedby="password-help"
                        />
                        <FieldDescription id="password-help">
                          Leave blank if your certificate has no password.
                          Nothing is saved to disk.
                        </FieldDescription>
                      </Field>
                      <Button
                        type="submit"
                        variant="secondary"
                        disabled={disabled}
                      >
                        Unlock certificate
                      </Button>
                    </FieldGroup>
                  </form>
                ) : (
                  <p className="text-sm leading-relaxed text-muted-foreground">
                    Your certificate identifies you and contains the private key
                    used to sign. You’ll review its details before signing.
                  </p>
                )}
              </CardContent>
              <CardFooter>
                <p className="text-sm text-muted-foreground">
                  File certificates only for now. Keychain, DNIe, and hardware
                  tokens come later.
                </p>
              </CardFooter>
            </Card>
          </div>
        )}

        {!saved && !review && (
          <section
            aria-label="Sign document"
            className="flex flex-wrap items-center justify-between gap-5 rounded-xl border bg-card p-5"
          >
            <div className="flex max-w-xl flex-col gap-1">
              <h2 className="font-medium">03 / Review and sign</h2>
              <p className="text-sm text-muted-foreground">
                {placement
                  ? `The signature box is on page ${placement.page + 1}.`
                  : "No visible box: the signature is in the file, not on a page."}{" "}
                Certificate trust and revocation are not checked.
              </p>
            </div>
            <Button
              size="lg"
              disabled={disabled || !document || !certificate}
              onClick={startReview}
            >
              Review and sign <ArrowRightIcon data-icon="inline-end" />
            </Button>
          </section>
        )}
        <p
          role="status"
          aria-live="polite"
          className="min-h-5 text-sm text-muted-foreground"
        >
          {working ??
            (saved
              ? "Your signed copy is ready."
              : review
                ? "Check the final preview, then sign."
                : document && certificate
                  ? "Ready. Confirm the document and certificate, then sign."
                  : "Choose a document and unlock a certificate to continue.")}
        </p>
      </main>
      <footer className="flex flex-col gap-5 pb-6">
        <Separator />
        <div className="flex flex-wrap justify-between gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-2">
            <ShieldCheckIcon className="size-3.5" aria-hidden="true" /> No
            uploads. No account. No Java.
          </span>
          <span>Garabato · First working version</span>
        </div>
      </footer>
    </div>
  );
}
