// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Link } from "react-router-dom";
import { ChevronRight, Loader2 } from "lucide-react";
import type { BatchRecord } from "@/lib/types";
import { batchCounts, batchElapsedMs, isBatchActive } from "@/lib/batch";
import { formatCost, formatMs, formatRelativeTime, shortId } from "@/lib/utils";
import { Progress } from "./ui";
import { VerdictMixBar } from "./VerdictMixBar";

export function BatchRow({ batch, now }: { batch: BatchRecord; now: number }) {
  const counts = batchCounts(batch);
  const active = isBatchActive(batch, now);
  return (
    <Link
      to={`/batch/${encodeURIComponent(batch.batch_id)}`}
      className="grid gap-3 px-5 py-4 transition-colors hover:bg-surface-2/40 sm:grid-cols-[1fr_14rem_auto] sm:items-center"
    >
      <div className="min-w-0 space-y-1">
        <p className="flex items-center gap-2 text-sm font-medium text-fg">
          {active && (
            <Loader2
              className="h-3.5 w-3.5 animate-spin text-accent"
              aria-label="Running"
            />
          )}
          Batch {shortId(batch.batch_id)}
          <span className="text-xs font-normal text-muted">
            {formatRelativeTime(batch.created_at)} via{" "}
            {batch.source.toUpperCase()}
          </span>
        </p>
        <Progress
          value={counts.done / Math.max(counts.total, 1)}
          tone={batch.error ? "danger" : active ? "accent" : "safe"}
        />
        {batch.error ? (
          <p className="text-xs text-danger">Failed: {batch.error}</p>
        ) : batch.awaiting_upload && active ? (
          <p className="text-xs text-fg-subtle">Waiting for the CSV upload</p>
        ) : (
          <p className="text-xs tabular-nums text-fg-subtle">
            {counts.done}/{counts.total} done, {counts.failed} failed,{" "}
            {formatMs(batchElapsedMs(batch, now))}, {formatCost(batch.cost_usd)}
          </p>
        )}
      </div>
      <VerdictMixBar counts={batch.verdict_counts} total={counts.total} />
      <ChevronRight
        className="hidden h-4 w-4 text-muted sm:block"
        aria-hidden
      />
    </Link>
  );
}
