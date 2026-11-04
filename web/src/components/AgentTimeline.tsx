// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { ScanRecord } from "@/lib/types";
import { buildTimeline, type TimelineRow } from "@/lib/timeline";
import { cn, formatMs } from "@/lib/utils";
import { Card, CardBody } from "./ui";

const STATUS_LABEL = {
  ok: "",
  error: "error",
  blocked_by_guardrail: "blocked",
} as const;

const STATUS_BAR = {
  error: "rgb(var(--danger))",
  blocked_by_guardrail: "rgb(var(--warn))",
} as const;

/** Quarter ticks on the shared time axis. */
const TICKS = [0, 0.25, 0.5, 0.75, 1];

/**
 * One accent for every bar (the specialist identity hues are too light on a white
 * surface to meet 3:1 as bars), a lighter step for sub-calls so a run reads as a
 * group, and the status colour for a failed or blocked call, which also says so
 * in text so status is never colour alone.
 */
function barColor(row: TimelineRow): string {
  if (row.status !== "ok") return STATUS_BAR[row.status];
  return "rgb(var(--accent))";
}

/** Waterfall of every AgentCore call in the scan: harness, specialists, browser, WHOIS. */
export function AgentTimeline({ record }: { record: ScanRecord }) {
  const { rows, totalMs } = buildTimeline(record);
  if (rows.length === 0)
    return (
      <p className="text-sm text-muted">
        No call timings were recorded for this scan.
      </p>
    );
  return (
    <Card>
      <CardBody className="space-y-1">
        <div
          className="hidden grid-cols-[minmax(0,13rem)_1fr_4.5rem] gap-3 pb-1 text-[11px] text-muted sm:grid"
          aria-hidden
        >
          <span>Call</span>
          <span className="relative h-4">
            {TICKS.map((t) => (
              <span
                key={t}
                className={cn(
                  "absolute top-0 tabular-nums",
                  t === 0
                    ? ""
                    : t === 1
                      ? "-translate-x-full"
                      : "-translate-x-1/2",
                )}
                style={{ left: `${t * 100}%` }}
              >
                {t === 0 ? "0" : formatMs(totalMs * t)}
              </span>
            ))}
          </span>
          <span className="text-right">Duration</span>
        </div>
        <ul className="space-y-1">
          {rows.map((row) => {
            const left = (row.offsetMs / totalMs) * 100;
            const width = Math.max(0.75, (row.durationMs / totalMs) * 100);
            const color = barColor(row);
            return (
              <li
                key={row.key}
                className={cn(
                  "grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 rounded-md px-1 py-1 text-xs sm:grid-cols-[minmax(0,13rem)_1fr_4.5rem]",
                  row.depth === 1 && "mt-1.5 bg-surface-2/50",
                )}
              >
                <span
                  className={cn(
                    "truncate font-mono",
                    row.depth === 2 ? "text-fg-subtle" : "font-medium text-fg",
                  )}
                  style={{ paddingLeft: `${row.depth * 0.875}rem` }}
                  title={`${row.kind}: ${row.label}`}
                >
                  {row.label}
                </span>
                <span
                  className="relative order-last col-span-2 h-2.5 rounded-full bg-surface-2 sm:order-0 sm:col-span-1"
                  aria-hidden
                >
                  {TICKS.slice(1, -1).map((t) => (
                    <span
                      key={t}
                      className="absolute inset-y-0 w-px bg-border"
                      style={{ left: `${t * 100}%` }}
                    />
                  ))}
                  <span
                    className="absolute inset-y-0 rounded-full"
                    style={{
                      left: `${left}%`,
                      width: `${width}%`,
                      background: color,
                      opacity: row.depth === 2 && row.status === "ok" ? 0.6 : 1,
                    }}
                  />
                </span>
                <span className="text-right tabular-nums text-fg-subtle">
                  {formatMs(row.durationMs)}
                  {STATUS_LABEL[row.status] && (
                    <span
                      className={cn(
                        "ml-1 font-medium",
                        row.status === "error" ? "text-danger" : "text-warn",
                      )}
                    >
                      {STATUS_LABEL[row.status]}
                    </span>
                  )}
                </span>
              </li>
            );
          })}
        </ul>
        <p className="pt-2 text-[11px] text-muted">
          {rows.length} calls over {formatMs(totalMs)}. Bars share one time axis
          starting at the first call; each specialist run is followed by its own
          model, browser, WHOIS and web search calls.
        </p>
      </CardBody>
    </Card>
  );
}
