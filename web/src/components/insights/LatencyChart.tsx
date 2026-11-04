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
} from "recharts";
import type { LatencyBucket } from "@/lib/types";
import { latencyRows } from "@/lib/insights";
import { SEQUENTIAL_COLOR } from "@/lib/verdictStyle";
import { useTheme } from "@/hooks/useTheme";
import { ChartCard } from "./ChartCard";

const AXIS_TICK = { fill: "rgb(var(--muted))", fontSize: 11 };

export function LatencyChart({ histogram }: { histogram: LatencyBucket[] }) {
  const { theme } = useTheme();
  const rows = latencyRows(histogram);
  return (
    <ChartCard
      title="Scan time distribution"
      subtitle="Number of scans by end-to-end time"
      table={{
        columns: ["Scan time", "Scans"],
        rows: rows.map((r) => [r.label, r.count]),
      }}
    >
      <ResponsiveContainer width="100%" height={220}>
        <BarChart
          data={rows}
          margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
          barCategoryGap="20%"
        >
          <CartesianGrid vertical={false} stroke="rgb(var(--border))" />
          <XAxis
            dataKey="label"
            // Every bucket is labelled; the default thinning hid alternate edges.
            interval={0}
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
            contentStyle={{
              background: "rgb(var(--surface))",
              border: "1px solid rgb(var(--border))",
              borderRadius: 8,
              fontSize: 12,
            }}
            formatter={(value: number) => [value, "Scans"]}
          />
          <Bar
            dataKey="count"
            fill={SEQUENTIAL_COLOR[theme]}
            radius={[4, 4, 0, 0]}
            // Bars tween by index from the previous histogram; draw final positions.
            isAnimationActive={false}
          />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
