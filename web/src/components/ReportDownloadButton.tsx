// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from "react";
import { FileDown } from "lucide-react";
import type { ReportLink } from "@/lib/api";
import { startDownload } from "@/lib/download";
import { Button, Spinner } from "./ui";

/**
 * Downloads the backend's HTML report. The link is fetched on click, never
 * cached, because presigned URLs expire after 15 minutes.
 */
export function ReportDownloadButton({
  fetchLink,
  label = "Download report",
  disabledReason,
}: {
  fetchLink: () => Promise<ReportLink>;
  label?: string;
  /** When set the button is disabled and this explains why (e.g. report still pending). */
  disabledReason?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    if (busy || disabledReason) return;
    setBusy(true);
    setError(null);
    try {
      startDownload((await fetchLink()).url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The report could not be downloaded.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="inline-flex flex-wrap items-center gap-3">
      {/* The span carries the tooltip: a disabled button gets no pointer events. */}
      <span title={disabledReason}>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => void run()}
          aria-busy={busy}
          disabled={Boolean(disabledReason)}
          aria-label={disabledReason ? `${label}. ${disabledReason}` : undefined}
        >
          {busy ? (
            <Spinner className="h-3.5 w-3.5" />
          ) : (
            <FileDown className="h-3.5 w-3.5" aria-hidden />
          )}
          {label}
        </Button>
      </span>
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
