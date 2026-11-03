// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Link } from "react-router-dom";
import type { BatchRecord } from "@/lib/types";
import { batchCounts } from "@/lib/batch";
import { formatCost, formatMs, formatRelativeTime, shortId } from "@/lib/utils";
import { VerdictMixBar } from "@/components/VerdictMixBar";
import { Card, CardBody } from "@/components/ui";

export function RecentBatchesTable({ batches }: { batches: BatchRecord[] }) {
  return (
    <Card>
      <CardBody className="space-y-3">
        <h3 className="text-sm font-semibold text-fg">Recent batches</h3>
        {batches.length === 0 && (
          <p className="text-xs text-muted">No batches in this range.</p>
        )}
        <ul className="divide-y divide-border">
          {batches.map((b) => (
            <li key={b.batch_id}>
              <Link
                to={`/batch/${encodeURIComponent(b.batch_id)}`}
                className="grid gap-2 py-3 text-xs transition-colors hover:bg-surface-2/40 sm:grid-cols-[8rem_1fr_16rem] sm:items-center"
              >
                <span className="font-mono text-fg">{shortId(b.batch_id)}</span>
                <span className="tabular-nums text-fg-subtle">
                  {b.total} URLs, {formatMs(b.wall_clock_ms)},{" "}
                  {formatCost(b.cost_usd)}, {formatRelativeTime(b.created_at)}
                </span>
                <VerdictMixBar
                  counts={b.verdict_counts}
                  total={batchCounts(b).total}
                />
              </Link>
            </li>
          ))}
        </ul>
      </CardBody>
    </Card>
  );
}
