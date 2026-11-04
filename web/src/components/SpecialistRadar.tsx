// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import {
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  type TooltipProps,
} from "recharts";
import type { Finding } from "@/lib/types";
import {
  RADAR_DOMAIN,
  radarRows,
  radarSeries,
  type RadarRow,
} from "@/lib/specialistRadar";
import { CHART_VERDICTS, VERDICT_STYLE, chartColor } from "@/lib/verdictStyle";
import { cn } from "@/lib/utils";
import { useTheme } from "@/hooks/useTheme";
import { DisclaimerBadge } from "./DisclaimerBanner";
import { ChartCard } from "./insights/ChartCard";
import { SPECIALIST_VISUAL } from "./specialistVisual";
import { VerdictIcon } from "./VerdictBadge";

const AXIS_TICK = { fill: "rgb(var(--fg-subtle))", fontSize: 11 };

function rowVerdict(row: RadarRow): { label: string; confidence: number } {
  for (const v of ["phishing", "suspicious", "legitimate"] as const) {
    if (row[v] > 0) return { label: VERDICT_STYLE[v].label, confidence: row[v] };
  }
  return { label: row.note ?? "No verdict", confidence: 0 };
}

function RadarTooltip({ active, payload }: TooltipProps<number, string>) {
  const row = payload?.[0]?.payload as RadarRow | undefined;
  if (!active || !row) return null;
  const { label, confidence } = rowVerdict(row);
  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-2 text-xs shadow-card">
      <p className="mb-1 font-semibold text-fg">
        {SPECIALIST_VISUAL[row.agent].label}
      </p>
      <p className="text-fg-subtle">
        {label}
        {confidence > 0 && (
          <span className="tabular-nums text-fg">, {confidence}% confident</span>
        )}
      </p>
    </div>
  );
}

function rowChartVerdict(row: RadarRow): (typeof CHART_VERDICTS)[number] | null {
  return CHART_VERDICTS.find((v) => row[v] > 0) ?? null;
}

/** Each specialist's verdict and confidence as text and a bar in the verdict color. */
function RadarReadout({ rows }: { rows: RadarRow[] }) {
  const { theme } = useTheme();
  return (
    <ul aria-label="Specialist readout" className="space-y-4">
      {rows.map((row) => {
        const visual = SPECIALIST_VISUAL[row.agent];
        const Icon = visual.icon;
        const v = rowChartVerdict(row);
        const { label, confidence } = rowVerdict(row);
        return (
          <li key={row.agent} data-agent={row.agent} className="space-y-1.5">
            <div className="flex items-center gap-2 text-sm">
              <Icon
                className="h-4 w-4 shrink-0"
                style={{ color: visual.color }}
                aria-hidden
              />
              <span className="font-medium text-fg">{visual.label}</span>
              <span className="ml-auto inline-flex items-center gap-1 text-xs text-fg-subtle">
                {v && <VerdictIcon verdict={v} className="h-3.5 w-3.5" />}
                {/* One flex item: the parent's gap would open "Phishing , 85%". */}
                <span data-verdict-text>
                  {label}
                  {v && (
                    <span className="tabular-nums text-fg">{`, ${confidence}%`}</span>
                  )}
                </span>
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-surface-2" aria-hidden>
              <div
                data-bar
                className="h-full rounded-full"
                style={{
                  width: `${confidence}%`,
                  background: v ? chartColor(v, theme) : undefined,
                }}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

type RadarDatum = RadarRow & { specialist: string };

/**
 * The polar plot. Grid, axes and every series share the chart's one centre and
 * radius. Animation is off: Recharts tweens a Radar from its previous points,
 * so when the responsive container resized after mount (the card filling its
 * grid column) a capture mid-tween drew a small polygon off the grid's centre.
 * `width` and `height` are passed by ResponsiveContainer, or by tests.
 */
export function RadarPlot({
  data,
  width,
  height,
}: {
  data: RadarDatum[];
  width?: number;
  height?: number;
}) {
  const { theme } = useTheme();
  return (
    <RadarChart
      data={data}
      width={width}
      height={height}
      // The triangle sits high in its circle; dropping the centre keeps it
      // visually centred in the plot.
      cy="58%"
      outerRadius="84%"
      margin={{ top: 16, right: 40, bottom: 8, left: 40 }}
    >
      <PolarGrid stroke="rgb(var(--border))" />
      <PolarAngleAxis dataKey="specialist" tick={AXIS_TICK} />
      <PolarRadiusAxis domain={RADAR_DOMAIN} tick={false} axisLine={false} />
      <Tooltip content={<RadarTooltip />} />
      {CHART_VERDICTS.map((v) => (
        <Radar
          key={v}
          name={VERDICT_STYLE[v].label}
          dataKey={v}
          stroke={chartColor(v, theme)}
          strokeWidth={2}
          fill={chartColor(v, theme)}
          fillOpacity={0.3}
          dot={{ r: 4, strokeWidth: 2, stroke: "rgb(var(--surface))" }}
          isAnimationActive={false}
        />
      ))}
    </RadarChart>
  );
}

/**
 * v1's ConvictionRadar, rebuilt on v2 findings: one axis per specialist and one
 * series per verdict, so the shape shows at a glance who called what, and how
 * sure each specialist was. Colors come from the verdict palette.
 */
export function SpecialistRadar({ findings }: { findings: Finding[] }) {
  const { theme } = useTheme();
  const rows = radarRows(findings);
  const series = radarSeries(rows);
  const data = rows.map((r) => ({
    ...r,
    specialist: SPECIALIST_VISUAL[r.agent].label,
  }));
  const legend = (
    <ul
      aria-label="Radar legend"
      className="flex flex-wrap gap-4 text-xs text-fg-subtle"
    >
      {series.map(({ verdict: v, empty }) => (
        <li
          key={v}
          data-verdict={v}
          data-empty={String(empty)}
          className={cn(
            "inline-flex items-center gap-1.5",
            empty && "text-muted",
          )}
        >
          <span
            className={cn("h-2.5 w-2.5 rounded-xs", empty && "opacity-40")}
            style={{ background: chartColor(v, theme) }}
            aria-hidden
          />
          <VerdictIcon verdict={v} className="h-3.5 w-3.5" />
          {VERDICT_STYLE[v].label}
          {empty && <span className="sr-only"> (no specialist)</span>}
        </li>
      ))}
    </ul>
  );
  return (
    <ChartCard
      title="Specialist confidence by verdict"
      subtitle="Each axis is a specialist; the distance out is its confidence in the verdict it reached"
      legend={legend}
      table={{
        columns: ["Specialist", "Verdict", "Confidence"],
        rows: rows.map((r) => {
          const { label, confidence } = rowVerdict(r);
          return [SPECIALIST_VISUAL[r.agent].label, label, `${confidence}%`];
        }),
      }}
    >
      <DisclaimerBadge className="mb-3" />
      {series.every((s) => s.empty) ? (
        <p className="py-8 text-center text-sm text-muted">
          No specialist reached a verdict, so there is nothing to plot.
        </p>
      ) : (
        // A three-axis radar is a triangle, so on a wide card it sits in a lot of
        // empty space. The readout takes the other half on desktop and stacks
        // under the chart on a phone; the plot height grows with the viewport.
        <div
          data-testid="radar-layout"
          className="grid items-center gap-4 lg:grid-cols-2"
        >
          <div data-testid="radar-plot" className="h-64 w-full sm:h-80 lg:h-96">
            <ResponsiveContainer width="100%" height="100%">
              <RadarPlot data={data} />
            </ResponsiveContainer>
          </div>
          <RadarReadout rows={rows} />
        </div>
      )}
    </ChartCard>
  );
}
