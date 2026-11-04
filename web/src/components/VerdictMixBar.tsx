// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { VerdictLabel } from "@/lib/types";
import { CHART_VERDICTS, VERDICT_STYLE, chartColor } from "@/lib/verdictStyle";
import { useTheme } from "@/hooks/useTheme";

/**
 * A compact stacked bar of verdict shares. The 2px gaps come from the surface-
 * coloured gap between segments, and the text line carries the numbers, so the
 * bar is never read by colour alone.
 */
export function VerdictMixBar({
  counts,
  total,
}: {
  counts: Partial<Record<VerdictLabel, number>>;
  total: number;
}) {
  const { theme } = useTheme();
  const parts = CHART_VERDICTS.map((v) => ({ v, n: counts[v] ?? 0 })).filter(
    (p) => p.n > 0,
  );
  // Error 404 and Site down are not chart series, but they must not vanish from
  // the mix: they share one neutral segment and are always named in the text line.
  const neutral = (["error_404", "site_down"] as const)
    .map((v) => ({ v, n: counts[v] ?? 0 }))
    .filter((p) => p.n > 0);
  const nNeutral = neutral.reduce((sum, p) => sum + p.n, 0);
  const summary = [...parts, ...neutral]
    .map((p) => `${p.n} ${VERDICT_STYLE[p.v].label.toLowerCase()}`)
    .join(", ");
  return (
    <div className="space-y-1">
      <div
        className="flex h-2 gap-[2px] overflow-hidden rounded-full bg-surface-2"
        aria-hidden
      >
        {parts.map((p) => (
          <span
            key={p.v}
            className="h-full transition-all duration-500"
            style={{
              width: `${(p.n / Math.max(total, 1)) * 100}%`,
              background: chartColor(p.v, theme),
            }}
          />
        ))}
        {nNeutral > 0 && (
          <span
            className="h-full bg-fg/30 transition-all duration-500"
            style={{ width: `${(nNeutral / Math.max(total, 1)) * 100}%` }}
          />
        )}
      </div>
      <p className="text-[11px] text-fg-subtle">
        {summary || "No verdicts yet"}
      </p>
    </div>
  );
}
