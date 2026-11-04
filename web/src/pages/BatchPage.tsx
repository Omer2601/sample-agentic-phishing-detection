// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Layers, Upload } from "lucide-react";
import { api } from "@/lib/api";
import { uploadToPresignedPost } from "@/lib/http";
import {
  JSON_BATCH_MAX,
  UI_BATCH_MAX,
  parseUrlList,
  toCsv,
} from "@/lib/urlList";
import { useActiveBatches } from "@/hooks/useActiveBatches";
import { useNow } from "@/hooks/useNow";
import { BatchRow } from "@/components/BatchRow";
import { Button, Card, CardBody, Spinner } from "@/components/ui";
import { EmptyState } from "@/components/ui/states";

const SAMPLE = `https://paypa1-secure-login.example/verify
https://www.iana.org
https://drive-google.com-share.example/doc
https://en.wikipedia.org`;

export function BatchPage() {
  const navigate = useNavigate();
  const { batches, active, loaded, refresh } = useActiveBatches();
  const now = useNow(1000, active.length > 0);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const parsed = useMemo(() => parseUrlList(text), [text]);
  const count = parsed.urls.length;
  const tooMany = count > UI_BATCH_MAX;

  const submit = async () => {
    setError(null);
    setSubmitting(true);
    try {
      let batchId: string;
      if (count <= JSON_BATCH_MAX) {
        batchId = (await api.startBatch(parsed.urls)).batch_id;
      } else {
        // Large lists go straight to S3 so the body never meets the edge WAF.
        const ticket = await api.requestUpload(count);
        const csv = new Blob([toCsv(parsed.urls)], { type: "text/csv" });
        await uploadToPresignedPost(
          ticket.upload_url,
          ticket.upload_fields,
          csv,
          `${ticket.batch_id}.csv`,
        );
        batchId = ticket.batch_id;
      }
      await refresh();
      navigate(`/batch/${encodeURIComponent(batchId)}`);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to submit the batch.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  const onFile = async (file: File) => {
    setError(null);
    setText(await file.text());
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-extrabold tracking-tight text-fg">
          Batch scan
        </h1>
        <p className="mt-1 text-sm text-fg-subtle">
          Paste URLs or upload a CSV (URL in the first column, header optional).
          Up to {UI_BATCH_MAX} per batch here; use the API for up to 1,000.
          Status is kept on the server, so you can leave this page at any time.
        </p>
      </header>

      <Card>
        <CardBody>
          <label htmlFor="batch-urls" className="text-sm font-semibold text-fg">
            URLs (one per line)
          </label>
          <textarea
            id="batch-urls"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={7}
            placeholder={SAMPLE}
            className="mt-2 w-full rounded-xl border border-border bg-surface p-3 font-mono text-xs text-fg placeholder:text-muted focus-visible:border-accent"
          />
          <p className="mt-2 text-xs text-fg-subtle" aria-live="polite">
            {count} ready
            {parsed.duplicates
              ? `, ${parsed.duplicates} duplicate${parsed.duplicates === 1 ? "" : "s"} removed`
              : ""}
            {parsed.invalid ? `, ${parsed.invalid} invalid skipped` : ""}
          </p>
          {tooMany && (
            <p className="mt-1 text-xs text-danger" role="alert">
              The console accepts at most {UI_BATCH_MAX} URLs per batch. Split
              the file, or use POST /batches from the API for up to 1,000.
            </p>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button
              onClick={() => void submit()}
              disabled={submitting || count === 0 || tooMany}
            >
              {submitting ? (
                <Spinner className="h-4 w-4" />
              ) : (
                <Layers className="h-4 w-4" />
              )}
              Scan {count} URLs
            </Button>
            <Button
              variant="secondary"
              onClick={() => fileInput.current?.click()}
              disabled={submitting}
            >
              <Upload className="h-4 w-4" /> Upload CSV
            </Button>
            <input
              ref={fileInput}
              type="file"
              accept=".csv,text/csv,text/plain"
              className="sr-only"
              aria-label="CSV file"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void onFile(f);
                e.target.value = "";
              }}
            />
            <button
              type="button"
              onClick={() => setText(SAMPLE)}
              className="text-xs font-medium text-muted underline-offset-4 hover:text-fg hover:underline"
            >
              Load sample
            </button>
          </div>
          {error && (
            <p className="mt-2 text-xs text-danger" role="alert">
              {error}
            </p>
          )}
        </CardBody>
      </Card>

      <section aria-label="Your batches" className="space-y-3">
        <h2 className="text-lg font-bold tracking-tight text-fg">
          Your batches
        </h2>
        {loaded && batches.length === 0 ? (
          <EmptyState
            icon={<Layers className="h-6 w-6" />}
            title="No batches yet"
            description="Submit a list above to start one."
          />
        ) : (
          <Card>
            <CardBody className="divide-y divide-border p-0">
              {batches.map((b) => (
                <BatchRow key={b.batch_id} batch={b} now={now} />
              ))}
            </CardBody>
          </Card>
        )}
      </section>
    </div>
  );
}
