import { ArrowLeftIcon, ArrowRightIcon, EyeOffIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import type { PDFDocumentProxy } from "@/lib/pdf";
import type { CertificateInfo, Placement } from "../../../shared/contracts";
import { PdfPage } from "./pdf-page";

/** The final check before signing: the drawn box and the signer identity. */
export function SignatureReview({
  preview,
  placement,
  certificate,
  disabled,
  onBack,
  onSign,
}: {
  /** The unsigned copy with the box drawn by the main process. */
  preview: PDFDocumentProxy | null;
  placement: Placement | null;
  certificate: CertificateInfo;
  disabled: boolean;
  onBack(): void;
  onSign(): void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>03 / Review and sign</h2>
        </CardTitle>
        <CardDescription>
          Check the page and the certificate. Nothing is saved until you sign.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid items-start gap-6 lg:grid-cols-[1.2fr_1fr]">
        {placement && preview ? (
          <div className="max-h-[560px] overflow-auto rounded-lg border bg-muted p-4">
            <PdfPage
              pdf={preview}
              page={placement.page}
              zoom={0.75}
              label={`Final preview of page ${placement.page + 1} with the signature box`}
            />
          </div>
        ) : (
          <Empty className="min-h-64 border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <EyeOffIcon />
              </EmptyMedia>
              <EmptyTitle>
                {placement ? "Preview is not available" : "No visible box"}
              </EmptyTitle>
              <EmptyDescription>
                {placement
                  ? `The box will be on page ${placement.page + 1}.`
                  : "The signature is stored in the file. No page shows a mark."}
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        )}
        <div className="flex flex-col gap-5">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-3 text-sm">
            <dt className="text-muted-foreground">Signer</dt>
            <dd className="break-words font-medium">{certificate.signer}</dd>
            <dt className="text-muted-foreground">Subject</dt>
            <dd className="break-words">{certificate.subject}</dd>
            <dt className="text-muted-foreground">Issuer</dt>
            <dd className="break-words">{certificate.issuer}</dd>
            <dt className="text-muted-foreground">Expires</dt>
            <dd>{new Date(certificate.validTo).toLocaleDateString()}</dd>
            <dt className="text-muted-foreground">Visible box</dt>
            <dd>
              {placement
                ? `Page ${placement.page + 1}. The date is set when you sign.`
                : "None"}
            </dd>
          </dl>
          <p className="break-all font-mono text-xs text-muted-foreground">
            SHA-256 · {certificate.fingerprint}
          </p>
          <Alert>
            <AlertTitle>The box is not the proof</AlertTitle>
            <AlertDescription>
              Anyone can draw a similar box. PDF readers check the digital
              signature separately, from the certificate and the signed bytes.
            </AlertDescription>
          </Alert>
        </div>
      </CardContent>
      <CardFooter className="flex flex-wrap justify-between gap-3">
        <Button variant="outline" disabled={disabled} onClick={onBack}>
          <ArrowLeftIcon data-icon="inline-start" /> Back
        </Button>
        <Button size="lg" disabled={disabled} onClick={onSign}>
          Sign and save copy <ArrowRightIcon data-icon="inline-end" />
        </Button>
      </CardFooter>
    </Card>
  );
}
