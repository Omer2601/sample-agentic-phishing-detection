// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useCallback, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  CircleCheck,
  CircleX,
  Loader2,
  TriangleAlert,
} from "lucide-react";
import { api } from "@/lib/api";
import {
  batchCounts,
  batchElapsedMs,
  estimateEtaMs,
  isBatchActive,
} from "@/lib/batch";
import type { BatchDetail } from "@/lib/types";
import { formatCost, formatMs, formatP95, shortId } from "@/lib/utils";
import { isReportPending } from "@/lib/scanProgress";
import { usePolling } from "@/hooks/usePolling";
import { useNow } from "@/hooks/useNow";
import { BATCH_POLL_MS, useActiveBatches } from "@/hooks/useActiveBatches";
import { DisclaimerBadge } from "@/components/DisclaimerBanner";
import { ReportDownloadButton } from "@/components/ReportDownloadButton";
import { RetryButton } from "@/components/RetryButton";
import { VerdictBadge, RiskPill } from "@/components/VerdictBadge";
import { ReportPendingHint } from "@/components/ReportPendingHint";
import { VerdictMixBar } from "@/components/VerdictMixBar";
import { Button, Card, CardBody, Progress, Spinner } from "@/components/ui";
import { ErrorState } from "@/components/ui/states";

function Tile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/40 px-4 py-3">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-0.5 text-xl font-bold tabular-nums text-fg">{value}</p>
    </div>
  );
}

// About five minutes of extra polling (150 polls at BATCH_POLL_MS = 2 s) after the batch ended.
const MAX_TAIL_POLLS = 150;

export function BatchDetailPage() {
  const { batchId = "" } = useParams();
  const { refresh: refreshBatches } = useActiveBatches();
  const [detail, setDetail] = useState<BatchDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Polls made after the batch ended, while some reports were still being written.
  const [tailPolls, setTailPolls] = useState(0);

  const load = useCallback(async () => {
    try {
      const next = await api.getBatch(batchId);
      setDetail(next);
      if (!isBatchActive(next.batch)) setTailPolls((n) => n + 1);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not load this batch.",
      );
    }
  }, [batchId]);

  // A batch ends when every verdict is in, but reports are written afterwards: keep
  // refreshing while any row still shows "Report pending", for a bounded time so a
  // report that never finishes cannot keep this page polling forever.
  const reportsPending =
    detail !== null &&
    tailPolls < MAX_TAIL_POLLS &&
    detail.items.some((item) => isReportPending(item));
  const active =
    detail === null || isBatchActive(detail.batch) || reportsPending;
  // A failed poll does not stop polling: a transient gateway error must not
  // freeze a running batch view. The error is shown until a poll succeeds.
  usePolling(load, BATCH_POLL_MS, active);
  const now = useNow(1000, active);

  const retryNow = (
    <Button variant="secondary" size="sm" onClick={() => void load()}>
      Retry now
    </Button>
  );

  if (error && !detail)
    return (
      <ErrorState
        title="This batch could not be loaded"
        description={error}
        action={retryNow}
      />
    );
  if (!detail) {
    return (
      <Card>
        <CardBody className="flex items-center gap-2 text-sm text-muted">
          <Spinner className="h-4 w-4" /> Loading the batch
        </CardBody>
      </Card>
    );
  }

  const { batch, items, invalid_rows: invalidRows } = detail;
  const counts = batchCounts(batch);
  const eta = estimateEtaMs(batch, now);

  return (
    <div className="space-y-6">
      <Link
        to="/batch"
        className="inline-flex items-center gap-1.5 text-xs font-medium text-muted hover:text-fg"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> All batches
      </Link>
      {error && (
        <div
          role="alert"
          className="flex flex-wrap items-center gap-3 rounded-xl border border-danger/30 bg-danger/5 px-4 py-3 text-sm"
        >
          <TriangleAlert className="h-4 w-4 shrink-0 text-danger" />
          <span className="flex-1 text-fg-subtle">
            Could not refresh this batch ({error}). Showing the last loaded
            state; it will keep trying.
          </span>
          {retryNow}
        </div>
      )}
      <header className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h1 className="text-2xl font-extrabold tracking-tight text-fg">
            Batch {shortId(batch.batch_id)}
          </h1>
          <ReportDownloadButton
            fetchLink={() => api.getBatchReport(batch.batch_id)}
          />
        </div>
        <Progress
          value={counts.done / Math.max(counts.total, 1)}
          tone="accent"
        />
      </header>

      {detail.error && (
        <ErrorState title="The upload could not be processed" description={detail.error} />
      )}
      {invalidRows.length > 0 && (
        <p className="text-xs text-fg-subtle">
          {invalidRows.length === 1
            ? "1 invalid row in the upload was skipped."
            : `${invalidRows.length} invalid rows in the upload were skipped.`}
        </p>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
        <Tile label="Done" value={`${counts.done}/${counts.total}`} />
        <Tile label="Failed" value={String(counts.failed)} />
        <Tile
          label={active ? "Elapsed" : "Wall clock"}
          value={formatMs(batchElapsedMs(batch, now))}
        />
        <Tile
          label="Remaining"
          value={
            eta === null ? (active ? "estimating" : "none") : formatMs(eta)
          }
        />
        <Tile
          label="Avg per URL"
          value={
            counts.done ? formatMs(batch.sum_scan_ms / counts.done) : "n/a"
          }
        />
        <Tile
          label="p50 per URL"
          value={formatP95(detail.p50_ms, detail.p50_over_max, detail.p50_bound)}
        />
        <Tile
          label="p95 per URL"
          value={formatP95(detail.p95_ms, detail.p95_over_max, detail.p95_bound)}
        />
        <Tile label="Token cost" value={formatCost(batch.cost_usd)} />
      </div>

      {counts.failed > 0 && (
        <RetryButton
          label={`Retry ${counts.failed} failed`}
          onRetry={async () => {
            await api.retryFailed(batch.batch_id);
            // The batch is running again: refresh this view and the header indicator.
            await Promise.all([load(), refreshBatches()]);
          }}
        />
      )}

      <VerdictMixBar counts={batch.verdict_counts} total={counts.total} />

      <Card>
        <CardBody className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted">
                <th className="px-3 py-2.5 font-medium sm:px-5">URL</th>
                <th className="hidden px-5 py-2.5 font-medium md:table-cell">Status</th>
                <th className="px-3 py-2.5 font-medium sm:px-5">
                  <span className="block">Verdict</span>
                  <DisclaimerBadge className="mt-1 hidden sm:inline-flex" />
                </th>
                <th className="px-3 py-2.5 text-right font-medium sm:px-5">Risk</th>
                <th className="hidden px-5 py-2.5 text-right font-medium sm:table-cell">Time</th>
                <th className="hidden px-5 py-2.5 text-right font-medium sm:table-cell">Cost</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr
                  key={item.scan_id}
                  className="border-b border-border/60 last:border-0 hover:bg-surface-2/40"
                >
                  <td
                    className="max-w-36 truncate px-3 py-2.5 font-mono text-xs sm:max-w-[280px] sm:px-5"
                    title={item.url}
                  >
                    <Link
                      to={`/results/${encodeURIComponent(item.scan_id)}`}
                      className="text-fg-subtle hover:text-accent"
                    >
                      {item.url}
                    </Link>
                  </td>
                  <td className="hidden px-5 py-2.5 text-xs md:table-cell">
                    {item.status === "COMPLETE" && (
                      <span className="flex flex-col gap-0.5">
                        <span className="inline-flex items-center gap-1.5 text-safe">
                          <CircleCheck className="h-3.5 w-3.5" /> Done
                        </span>
                        <ReportPendingHint item={item} />
                      </span>
                    )}
                    {item.status === "FAILED" && (
                      <span className="flex flex-col gap-0.5">
                        <span className="inline-flex items-center gap-1.5 text-danger">
                          <CircleX className="h-3.5 w-3.5" /> Failed
                        </span>
                        <span className="max-w-[16rem] text-[11px] text-fg-subtle">
                          {item.error?.trim() || "No reason recorded; retry it."}
                        </span>
                      </span>
                    )}
                    {(item.status === "PENDING" ||
                      item.status === "RUNNING") && (
                      <span className="inline-flex items-center gap-1.5 text-accent">
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />{" "}
                        {item.status === "PENDING" ? "Queued" : "Scanning"}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 sm:px-5">
                    {item.verdict ? (
                      <span className="flex flex-col items-start gap-0.5">
                        <VerdictBadge verdict={item.verdict.verdict} />
                        {/* The status column is hidden below md, so repeat the hint here there. */}
                        <span className="md:hidden">
                          <ReportPendingHint item={item} />
                        </span>
                      </span>
                    ) : (
                      // The status column is hidden on narrow screens, so an
                      // unfinished row says why it has no verdict here instead.
                      <span className="text-xs text-fg-subtle md:hidden">
                        {item.status === "FAILED"
                          ? "Failed"
                          : item.status === "PENDING"
                            ? "Queued"
                            : item.status === "RUNNING"
                              ? "Scanning"
                              : null}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 text-right sm:px-5">
                    {item.verdict ? (
                      <RiskPill score={item.verdict.risk_score} />
                    ) : null}
                  </td>
                  <td className="hidden px-5 py-2.5 text-right text-xs tabular-nums text-fg-subtle sm:table-cell">
                    {formatMs(item.total_ms)}
                  </td>
                  <td className="hidden px-5 py-2.5 text-right text-xs tabular-nums text-fg-subtle sm:table-cell">
                    {formatCost(item.cost_usd)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardBody>
      </Card>
    </div>
  );
}
