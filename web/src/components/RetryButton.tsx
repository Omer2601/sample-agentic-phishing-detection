// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from "react";
import { RotateCcw } from "lucide-react";
import { ApiError } from "@/lib/api";
import { Button, Spinner } from "./ui";

/**
 * The retry routes answer 503 when the retry could not be queued. The request
 * already went through the shared 429/503 backoff (safe: both routes are
 * idempotent server-side), so this is the final answer and the user decides
 * whether to press again.
 */
export const RETRY_NOT_QUEUED_MESSAGE = "Could not queue the retry, try again.";

function retryErrorMessage(e: unknown): string {
  if (e instanceof ApiError && e.status === 503) return RETRY_NOT_QUEUED_MESSAGE;
  return e instanceof Error ? e.message : "Retry failed.";
}

/**
 * One retry action with its own busy and error state. A second click while a
 * retry is in flight is ignored, so a double click never queues two retries.
 */
export function RetryButton({
  onRetry,
  label,
}: {
  onRetry: () => Promise<unknown>;
  label: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await onRetry();
    } catch (e) {
      setError(retryErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button
        variant="secondary"
        size="sm"
        onClick={() => void run()}
        aria-busy={busy}
      >
        {busy ? (
          <Spinner className="h-3.5 w-3.5" />
        ) : (
          <RotateCcw className="h-3.5 w-3.5" aria-hidden />
        )}
        {busy ? "Retrying..." : label}
      </Button>
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
