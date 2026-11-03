// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type {
  AgentCoreStat,
  CallKind,
  DailyStats,
  LatencyBucket,
  StatsRange,
} from "./types";
import { formatMs, formatP95 } from "./utils";

export const INSIGHTS_POLL_MS = 5000;

export const RANGES: { id: StatsRange; label: string }[] = [
  { id: "24h", label: "24 hours" },
  { id: "7d", label: "7 days" },
  { id: "30d", label: "30 days" },
  { id: "all", label: "All time" },
];

/**
 * Buckets are UTC days on the server (UTC hours, "YYYY-MM-DDTHH", for the 24h
 * range); format in UTC so a label never shifts a day.
 */
export function dayLabel(day: string): string {
  const hour = /^(\d{4}-\d{2}-\d{2})T(\d{2})$/.exec(day);
  const date = new Date(`${hour ? hour[1] : day}T00:00:00Z`).toLocaleDateString(
    "en-US",
    { month: "short", day: "numeric", timeZone: "UTC" },
  );
  return hour ? `${date} ${hour[2]}:00` : date;
}

const RANGE_DAYS: Record<Exclude<StatsRange, "24h">, number> = {
  "7d": 7,
  "30d": 30,
  // The server charts the last 30 days for "all"; totals still cover all time.
  all: 30,
};

const pad = (n: number) => String(n).padStart(2, "0");
const dayKey = (d: Date) =>
  `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
const hourKey = (d: Date) => `${dayKey(d)}T${pad(d.getUTCHours())}`;

/** Parse a bucket key ("YYYY-MM-DD" or "YYYY-MM-DDTHH") as a UTC instant. */
function keyTime(key: string): number {
  const hour = /^(\d{4}-\d{2}-\d{2})T(\d{2})$/.exec(key);
  return Date.parse(hour ? `${hour[1]}T${hour[2]}:00:00Z` : `${key}T00:00:00Z`);
}

/**
 * The x axis for a range: every UTC day (or, for 24h, UTC hour) bucket, oldest
 * first, ending at the current bucket. The server buckets in UTC, so the client
 * must too, or a scan late in the evening west of Greenwich lands a day early.
 * The axis ends at the newer of the browser clock and the newest key the server
 * sent, so a slow browser clock never drops today's data.
 */
export function seriesKeys(
  range: StatsRange,
  now: Date,
  daily: DailyStats[],
): string[] {
  const newest = Math.max(
    now.getTime(),
    ...daily.map((d) => keyTime(d.day)).filter(Number.isFinite),
  );
  const end = new Date(newest);
  if (range === "24h") {
    return Array.from({ length: 24 }, (_, i) =>
      hourKey(new Date(end.getTime() - (23 - i) * 3_600_000)),
    );
  }
  const days = RANGE_DAYS[range];
  return Array.from({ length: days }, (_, i) =>
    dayKey(new Date(end.getTime() - (days - 1 - i) * 86_400_000)),
  );
}

/** Daily points keyed by bucket and placed on the range's axis; gaps are zeros. */
function joined(
  daily: DailyStats[],
  range: StatsRange,
  now: Date,
): { key: string; point: DailyStats | undefined }[] {
  const byKey = new Map(daily.map((d) => [d.day, d]));
  return seriesKeys(range, now, daily).map((key) => ({
    key,
    point: byKey.get(key),
  }));
}

export function verdictRows(daily: DailyStats[], range: StatsRange, now: Date) {
  return joined(daily, range, now).map(({ key, point }) => ({
    key,
    label: dayLabel(key),
    phishing: point?.phishing ?? 0,
    suspicious: point?.suspicious ?? 0,
    legitimate: point?.legitimate ?? 0,
  }));
}

export function costRows(daily: DailyStats[], range: StatsRange, now: Date) {
  return joined(daily, range, now).map(({ key, point }) => ({
    key,
    label: dayLabel(key),
    cost: Number.parseFloat(point?.cost_usd ?? "0") || 0,
  }));
}

/**
 * The backend's latency bucket upper bounds in ms (stats/updates.py
 * LAT_BUCKETS). The last one is open-ended.
 */
export const LATENCY_EDGES = [
  10_000, 20_000, 30_000, 40_000, 60_000, 90_000, 120_000, 999_999_999,
] as const;
const MAX_FINITE_EDGE = LATENCY_EDGES[LATENCY_EDGES.length - 2];

export function latencyLabel(upperMs: number): string {
  return upperMs > MAX_FINITE_EDGE
    ? `over ${MAX_FINITE_EDGE / 1000}s`
    : `up to ${Math.round(upperMs / 1000)}s`;
}

/** One row per backend bucket, counts joined by `upper_ms`, never by position. */
export function latencyRows(hist: LatencyBucket[]) {
  const counts = new Map<number, number>();
  for (const b of hist) {
    // Anything past the last finite edge belongs to the open bucket.
    const edge =
      LATENCY_EDGES.find((e) => b.upper_ms <= e) ??
      LATENCY_EDGES[LATENCY_EDGES.length - 1];
    counts.set(edge, (counts.get(edge) ?? 0) + b.count);
  }
  return LATENCY_EDGES.map((edge) => ({
    label: latencyLabel(edge),
    count: counts.get(edge) ?? 0,
  }));
}

const MODEL_NAMES: Record<string, string> = {
  "us.anthropic.claude-opus-5-5": "Claude Opus 5.5 (orchestrator)",
  "global.anthropic.claude-sonnet-5-5": "Claude Sonnet 5.5 (specialists)",
};

export function modelLabel(id: string): string {
  return MODEL_NAMES[id] ?? id;
}

const CALL_NAMES: Record<CallKind, string> = {
  harness: "Harness orchestration",
  specialist: "Specialist via Gateway",
  model: "Model call",
  browser: "Browser session",
  whois: "WHOIS lookup",
  web_search: "Web search",
  registry: "Registry lookup via Gateway",
};

export function callLabel(kind: CallKind): string {
  return CALL_NAMES[kind];
}

/**
 * The p95 to show for one AgentCore call row. A single call's average is its
 * exact duration, so it wins over any bucket edge (an older backend reported
 * 10 s for a 149 ms call). Without the backend's p95_bound flag the value is
 * assumed to be a bucket edge, which is all older backends could send.
 */
export function callP95(stat: AgentCoreStat): { ms: number; text: string } {
  if (stat.count === 1 && stat.avg_ms > 0) {
    return { ms: stat.avg_ms, text: formatMs(stat.avg_ms) };
  }
  return {
    ms: stat.p95_ms,
    text: formatP95(stat.p95_ms, stat.p95_over_max, stat.p95_bound ?? true),
  };
}
