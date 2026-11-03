// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { DailyStats, StatsRange } from "@/lib/types";
import { dayLabel, costRows } from "@/lib/insights";
import { SEQUENTIAL_COLOR } from "@/lib/verdictStyle";
import { formatCost } from "@/lib/utils";
import { useTheme } from "@/hooks/useTheme";
import { ChartCard } from "./ChartCard";

const AXIS_TICK = { fill: "rgb(var(--muted))", fontSize: 11 };

export function CostTrendChart({
  daily,
  range,
  now,
}: {
  daily: DailyStats[];
  range: StatsRange;
  now: Date;
}) {
  const { theme } = useTheme();
  const rows = costRows(daily, range, now);
  return (
    <ChartCard
      title="Token cost per day"
      subtitle="Bedrock tokens for the orchestrator and specialists"
      table={{
        columns: ["Day", "Cost"],
        rows: rows.map((r) => [r.label, formatCost(r.cost)]),
      }}
    >
      <ResponsiveContainer width="100%" height={220}>
        <LineChart
          data={rows}
          margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
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
            tickLine={false}
            axisLine={false}
            width={48}
            tick={AXIS_TICK}
            tickFormatter={(v: number) => `$${v}`}
          />
          <Tooltip
            contentStyle={{
              background: "rgb(var(--surface))",
              border: "1px solid rgb(var(--border))",
              borderRadius: 8,
              fontSize: 12,
            }}
            labelFormatter={(key: string) => dayLabel(key)}
            formatter={(value: number) => [formatCost(value), "Cost"]}
          />
          <Line
            type="linear"
            dataKey="cost"
            stroke={SEQUENTIAL_COLOR[theme]}
            strokeWidth={2}
            dot={{
              r: 4,
              strokeWidth: 2,
              stroke: "rgb(var(--surface))",
              fill: SEQUENTIAL_COLOR[theme],
            }}
            activeDot={{ r: 5 }}
            // A tween from the previous series moves points by index; see VerdictTrendChart.
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
