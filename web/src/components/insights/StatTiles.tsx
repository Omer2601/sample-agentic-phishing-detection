// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { ReactNode } from "react";
import { AlertOctagon, Clock, Coins, Cpu, Gauge, ScanLine } from "lucide-react";
import type { StatsTotals } from "@/lib/types";
import { formatCost, formatMs, formatP95, formatTokens } from "@/lib/utils";
import { VerdictIcon } from "@/components/VerdictBadge";

function Tile({
  icon,
  label,
  value,
  hint,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="card p-4">
      <div className="flex items-center gap-2 text-muted">
        {icon}
        <span className="text-xs font-medium">{label}</span>
      </div>
      <p className="mt-1.5 text-2xl font-bold tabular-nums text-fg">
        {value}
      </p>
      {hint && <p className="text-[11px] text-fg-subtle">{hint}</p>}
    </div>
  );
}

/** Headline numbers. Values wear text tokens; the icon next to each carries identity. */
export function StatTiles({ totals }: { totals: StatsTotals }) {
  const pct = (n: number) =>
    totals.scanned
      ? `${Math.round((n / totals.scanned) * 100)}% of scans`
      : undefined;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
      <Tile
        icon={<ScanLine className="h-4 w-4" />}
        label="URLs scanned"
        value={String(totals.scanned)}
      />
      <Tile
        icon={
          <VerdictIcon verdict="phishing" className="h-4 w-4 text-danger" />
        }
        label="Phishing"
        value={String(totals.phishing)}
        hint={pct(totals.phishing)}
      />
      <Tile
        icon={
          <VerdictIcon verdict="suspicious" className="h-4 w-4 text-warn" />
        }
        label="Suspicious"
        value={String(totals.suspicious)}
        hint={pct(totals.suspicious)}
      />
      <Tile
        icon={
          <VerdictIcon verdict="legitimate" className="h-4 w-4 text-safe" />
        }
        label="Legitimate"
        value={String(totals.legitimate)}
        hint={pct(totals.legitimate)}
      />
      <Tile
        icon={<AlertOctagon className="h-4 w-4" />}
        label="Failed or unknown"
        value={String(totals.failed + totals.unknown)}
        // Error 404 and Site down stay out of the value (a dead target is not a
        // failure) but are named in the hint so they are never hidden. Absent in
        // older data.
        hint={`${totals.failed} failed, ${totals.unknown} unknown, ${totals.error_404 ?? 0} Error 404, ${totals.site_down ?? 0} Site down`}
      />
      <Tile
        icon={<Coins className="h-4 w-4" />}
        label="Token cost"
        value={formatCost(totals.cost_usd)}
        hint={
          totals.unpriced_scans
            ? `At least: ${totals.unpriced_scans} scans used a model with no price`
            : undefined
        }
      />
      <Tile
        icon={<Cpu className="h-4 w-4" />}
        label="Tokens"
        value={formatTokens(totals.input_tokens + totals.output_tokens)}
        hint={`${formatTokens(totals.input_tokens)} in, ${formatTokens(totals.output_tokens)} out`}
      />
      <Tile
        icon={<Clock className="h-4 w-4" />}
        label="Average scan"
        value={formatMs(totals.avg_ms)}
      />
      <Tile
        icon={<Gauge className="h-4 w-4" />}
        label="p95 scan"
        value={formatP95(totals.p95_ms, totals.p95_over_max, totals.p95_bound)}
        hint="Target 30 to 40s"
      />
    </div>
  );
}
