// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipProps,
} from "recharts";
import type { DailyStats, StatsRange } from "@/lib/types";
import { dayLabel, verdictRows } from "@/lib/insights";
import { CHART_VERDICTS, VERDICT_STYLE, chartColor } from "@/lib/verdictStyle";
import { useTheme } from "@/hooks/useTheme";
import { VerdictIcon } from "@/components/VerdictBadge";
import { ChartCard } from "./ChartCard";

const AXIS_TICK = { fill: "rgb(var(--muted))", fontSize: 11 };

function VerdictTooltip({
  active,
  payload,
  label,
}: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-2 text-xs shadow-card">
      <p className="mb-1 font-semibold text-fg">{dayLabel(String(label))}</p>
      {[...payload].reverse().map((p) => (
        <p
          key={String(p.dataKey)}
          className="flex items-center gap-2 text-fg-subtle"
        >
          <span
            className="h-2 w-2 rounded-xs"
            style={{ background: p.color }}
            aria-hidden
          />
          {VERDICT_STYLE[p.dataKey as (typeof CHART_VERDICTS)[number]].label}:{" "}
          <span className="tabular-nums text-fg">{p.value}</span>
        </p>
      ))}
    </div>
  );
}

export function VerdictTrendChart({
  daily,
  range,
  now,
}: {
  daily: DailyStats[];
  range: StatsRange;
  now: Date;
}) {
  const { theme } = useTheme();
  const rows = verdictRows(daily, range, now);
  const legend = (
    <ul className="flex flex-wrap gap-4 text-xs text-fg-subtle">
      {CHART_VERDICTS.map((v) => (
        <li key={v} className="inline-flex items-center gap-1.5">
          <span
            className="h-2.5 w-2.5 rounded-xs"
            style={{ background: chartColor(v, theme) }}
            aria-hidden
          />
          <VerdictIcon verdict={v} className="h-3.5 w-3.5" />
          {VERDICT_STYLE[v].label}
        </li>
      ))}
    </ul>
  );
  return (
    <ChartCard
      title="Scans per day by verdict"
      subtitle="Failed, unknown, Error 404 and Site down scans are counted in the tiles above"
      legend={legend}
      table={{
        columns: ["Day", "Phishing", "Suspicious", "Legitimate"],
        rows: rows.map((r) => [
          r.label,
          r.phishing,
          r.suspicious,
          r.legitimate,
        ]),
      }}
    >
      <ResponsiveContainer width="100%" height={240}>
        <BarChart
          data={rows}
          margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
          barCategoryGap="24%"
        >
          <CartesianGrid vertical={false} stroke="rgb(var(--border))" />
          <XAxis
            dataKey="key"
            tickFormatter={(key: string) => dayLabel(key)}
            tickLine={false}
            axisLine={false}
            tick={AXIS_TICK}
          />
          <YAxis
            allowDecimals={false}
            tickLine={false}
            axisLine={false}
            width={32}
            tick={AXIS_TICK}
          />
          <Tooltip
            cursor={{ fill: "rgb(var(--surface-2))" }}
            content={<VerdictTooltip />}
          />
          {CHART_VERDICTS.map((v, i) => (
            <Bar
              key={v}
              dataKey={v}
              stackId="verdicts"
              fill={chartColor(v, theme)}
              stroke="rgb(var(--surface))"
              strokeWidth={2}
              radius={i === CHART_VERDICTS.length - 1 ? [4, 4, 0, 0] : 0}
              // Recharts tweens bars from the previous series by index, so a
              // capture mid-tween (or a range switch) drew today on another day.
              isAnimationActive={false}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
