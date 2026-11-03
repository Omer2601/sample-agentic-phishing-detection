// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { ScanForm } from "@/components/ScanForm";
import { ErrorState } from "@/components/ui/states";
import { Button } from "@/components/ui";

export function ScanPage() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = useCallback(
    async (url: string) => {
      setError(null);
      setSubmitting(true);
      try {
        const { scan_id } = await api.startScan(url);
        // The result page owns polling, so the scan keeps going if the user leaves.
        navigate(`/results/${encodeURIComponent(scan_id)}`);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to submit the scan.",
        );
      } finally {
        setSubmitting(false);
      }
    },
    [navigate],
  );

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-extrabold tracking-tight text-fg">
          Scan a URL
        </h1>
        <p className="mt-1 text-sm text-fg-subtle">
          One link, three specialist agents in parallel, one orchestrated
          verdict. About 30 to 40 seconds.
        </p>
      </header>
      {error ? (
        <ErrorState
          title="The scan could not start"
          description={error}
          action={
            <Button variant="secondary" onClick={() => setError(null)}>
              Try again
            </Button>
          }
        />
      ) : (
        <ScanForm
          onSubmit={(url) => void handleSubmit(url)}
          disabled={submitting}
        />
      )}
    </div>
  );
}
