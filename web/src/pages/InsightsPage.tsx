// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useCallback, useEffect, useRef, useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { INSIGHTS_POLL_MS } from "@/lib/insights";
import type { Stats, StatsRange } from "@/lib/types";
import { useActiveBatches } from "@/hooks/useActiveBatches";
import { usePolling } from "@/hooks/usePolling";
import { AgentCorePanel } from "@/components/insights/AgentCorePanel";
import { CostTrendChart } from "@/components/insights/CostTrendChart";
import { LatencyChart } from "@/components/insights/LatencyChart";
import { ModelUsageTable } from "@/components/insights/ModelUsageTable";
import { RangePicker } from "@/components/insights/RangePicker";
import { RecentBatchesTable } from "@/components/insights/RecentBatchesTable";
import { StatTiles } from "@/components/insights/StatTiles";
import { VerdictTrendChart } from "@/components/insights/VerdictTrendChart";
import { Skeleton } from "@/components/ui";
import { ErrorState } from "@/components/ui/states";

/**
 * Your scanning activity: volume and verdicts, time, tokens and cost, and
 * AgentCore behaviour. Refreshes every 5 s while one of your batches is running,
 * otherwise loads once per range.
 */
export function InsightsPage() {
  const [range, setRange] = useState<StatsRange>("7d");
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { active } = useActiveBatches();
  const live = active.length > 0;

  // Only the newest request may update the page. Switching range while a
  // slower request is in flight (or a poll overlapping a range change) would
  // otherwise let the older answer land last and show the wrong range.
  const latestRequest = useRef(0);
  const load = useCallback(async () => {
    const id = ++latestRequest.current;
    try {
      const next = await api.getStats(range);
      if (id !== latestRequest.current) return;
      setStats(next);
      setError(null);
    } catch (err) {
      if (id !== latestRequest.current) return;
      setError(
        err instanceof Error ? err.message : "Could not load your statistics.",
      );
    }
  }, [range]);

  useEffect(() => {
    void load();
  }, [load]);
  usePolling(load, INSIGHTS_POLL_MS, live);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-fg">
            Insights
          </h1>
          <p className="mt-1 inline-flex items-center gap-2 text-sm text-fg-subtle">
            Your scans, verdicts, time, tokens, cost and AgentCore activity.
            {live && (
              <span className="inline-flex items-center gap-1 text-accent">
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />{" "}
                live
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RangePicker value={range} onChange={setRange} />
          <a
            href={api.statsExportUrl(range)}
            download
            className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface-2 px-3 py-2 text-xs font-medium text-fg transition-colors hover:bg-surface-2/70"
          >
            <Download className="h-3.5 w-3.5" aria-hidden /> Export CSV
          </a>
        </div>
      </header>

      {error && <ErrorState description={error} />}

      {!stats && !error && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
          {Array.from({ length: 9 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-2xl" />
          ))}
        </div>
      )}

      {stats && (
        <>
          <StatTiles totals={stats.totals} />
          <div className="grid gap-4 lg:grid-cols-2">
            <VerdictTrendChart
              daily={stats.daily}
              range={stats.range}
              now={new Date()}
            />
            <LatencyChart histogram={stats.latency_histogram} />
            <CostTrendChart
              daily={stats.daily}
              range={stats.range}
              now={new Date()}
            />
            <ModelUsageTable models={stats.by_model} />
          </div>
          <AgentCorePanel stats={stats.agentcore} />
          <RecentBatchesTable batches={stats.recent_batches} />
        </>
      )}
    </div>
  );
}
