// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import {
  callLabel,
  costRows,
  dayLabel,
  latencyLabel,
  latencyRows,
  callP95,
  modelLabel,
  seriesKeys,
  verdictRows,
} from "./insights";
import type { DailyStats } from "./types";

const day = {
  day: "2026-09-29",
  phishing: 38,
  suspicious: 6,
  legitimate: 3,
  unknown: 1,
  error_404: 0,
  failed: 2,
  cost_usd: "7.48",
  input_tokens: 1,
  output_tokens: 1,
};

describe("insights transforms", () => {
  it("labels days in UTC without drifting a day", () => {
    expect(dayLabel("2026-09-29")).toBe("Sep 29");
  });
  it("labels 24h hour buckets (YYYY-MM-DDTHH) by UTC hour", () => {
    expect(dayLabel("2026-09-29T14")).toBe("Sep 29 14:00");
  });
  it("keeps only the charted verdicts per day", () => {
    const rows = verdictRows([day], "7d", NOW_SEP29);
    expect(rows.at(-1)).toEqual({
      key: "2026-09-29",
      label: "Sep 29",
      phishing: 38,
      suspicious: 6,
      legitimate: 3,
    });
  });
  it("parses cost strings to numbers for the chart", () => {
    expect(costRows([day], "7d", NOW_SEP29).at(-1)).toEqual({
      key: "2026-09-29",
      label: "Sep 29",
      cost: 7.48,
    });
  });
});

const NOW_SEP29 = new Date("2026-09-29T12:00:00Z");
// The live defect: 22:42 on Sep 30 in Seattle is 05:42 on Oct 1 UTC, and the
// one scan of the day landed in the server's Oct 1 bucket.
const LIVE_NOW = new Date("2026-10-01T05:42:00Z");

function point(dayKey: string, phishing: number, cost = "0"): DailyStats {
  return {
    day: dayKey,
    phishing,
    suspicious: 0,
    legitimate: 0,
    unknown: 0,
    failed: 0,
    cost_usd: cost,
    input_tokens: 0,
    output_tokens: 0,
  };
}

describe("daily series alignment", () => {
  it("builds the x axis from the range's UTC day buckets, oldest first", () => {
    expect(seriesKeys("7d", LIVE_NOW, [])).toEqual([
      "2026-09-25",
      "2026-09-26",
      "2026-09-27",
      "2026-09-28",
      "2026-09-29",
      "2026-09-30",
      "2026-10-01",
    ]);
    expect(seriesKeys("30d", LIVE_NOW, [])).toHaveLength(30);
    expect(seriesKeys("all", LIVE_NOW, []).at(-1)).toBe("2026-10-01");
  });

  it("joins daily points by day key, not by array position", () => {
    // Short, out of order: positional mapping would put today on Sep 26.
    const daily = [point("2026-10-01", 1, "0.1361"), point("2026-09-30", 0)];
    const rows = verdictRows(daily, "7d", LIVE_NOW);
    expect(rows.map((r) => r.label)).toEqual([
      "Sep 25",
      "Sep 26",
      "Sep 27",
      "Sep 28",
      "Sep 29",
      "Sep 30",
      "Oct 1",
    ]);
    expect(rows.map((r) => r.phishing)).toEqual([0, 0, 0, 0, 0, 0, 1]);
    const cost = costRows(daily, "7d", LIVE_NOW);
    expect(cost.map((r) => r.cost)).toEqual([0, 0, 0, 0, 0, 0, 0.1361]);
  });

  it("fills missing days with zeros", () => {
    const rows = verdictRows([], "7d", LIVE_NOW);
    expect(rows).toHaveLength(7);
    expect(rows.every((r) => r.phishing + r.suspicious + r.legitimate === 0)).toBe(true);
  });

  it("keeps the server's newest bucket when the browser clock is behind", () => {
    const behind = new Date("2026-09-30T23:59:00Z");
    const rows = verdictRows([point("2026-10-01", 2)], "7d", behind);
    expect(rows.at(-1)).toMatchObject({ key: "2026-10-01", phishing: 2 });
    expect(rows).toHaveLength(7);
  });

  it("joins 24h hour buckets by UTC hour key", () => {
    const keys = seriesKeys("24h", LIVE_NOW, []);
    expect(keys).toHaveLength(24);
    expect(keys[0]).toBe("2026-09-30T06");
    expect(keys.at(-1)).toBe("2026-10-01T05");
    const rows = verdictRows([point("2026-10-01T05", 1)], "24h", LIVE_NOW);
    expect(rows.at(-1)).toMatchObject({ label: "Oct 1 05:00", phishing: 1 });
    expect(rows.slice(0, -1).every((r) => r.phishing === 0)).toBe(true);
  });
});

describe("latency histogram", () => {
  it("labels latency buckets as upper bounds", () => {
    expect(latencyLabel(30_000)).toBe("up to 30s");
    expect(latencyLabel(999_999_999)).toBe("over 120s");
  });

  it("puts a 35 s scan under 'up to 40s' by bucket value, not position", () => {
    // Only the non-empty bucket, as a sparse or reordered payload would send it.
    const rows = latencyRows([{ upper_ms: 40_000, count: 1 }]);
    expect(rows.map((r) => r.label)).toEqual([
      "up to 10s",
      "up to 20s",
      "up to 30s",
      "up to 40s",
      "up to 60s",
      "up to 90s",
      "up to 120s",
      "over 120s",
    ]);
    expect(rows.find((r) => r.count > 0)?.label).toBe("up to 40s");
  });

  it("matches every backend bucket edge, including the open one", () => {
    const edges = [10000, 20000, 30000, 40000, 60000, 90000, 120000, 999999999];
    const rows = latencyRows(
      [...edges].reverse().map((upper_ms, i) => ({ upper_ms, count: i + 1 })),
    );
    expect(rows.map((r) => r.count)).toEqual([8, 7, 6, 5, 4, 3, 2, 1]);
  });
  it("names models and call kinds in plain words", () => {
    expect(modelLabel("us.anthropic.claude-opus-5-5")).toBe(
      "Claude Opus 5.5 (orchestrator)",
    );
    expect(modelLabel("global.anthropic.claude-sonnet-5-5")).toBe(
      "Claude Sonnet 5.5 (specialists)",
    );
    expect(modelLabel("other.model")).toBe("other.model");
    expect(callLabel("whois")).toBe("WHOIS lookup");
    expect(callLabel("web_search")).toBe("Web search");
    expect(callLabel("registry")).toBe("Registry lookup via Gateway");
  });
});

describe("AgentCore call p95", () => {
  const stat = {
    kind: "whois" as const,
    name: "whois_lookup",
    count: 1,
    avg_ms: 149,
    p95_ms: 10_000,
    p95_over_max: false,
    errors: 0,
    blocked: 0,
  };
  it("shows the one observed duration when there is a single call", () => {
    // An older backend reports the 10 s bucket edge for a 149 ms call.
    expect(callP95(stat)).toEqual({ ms: 149, text: "149 ms" });
  });
  it("never shows a p95 above the observed duration", () => {
    const p = callP95({ ...stat, avg_ms: 963 });
    expect(p.ms).toBeLessThanOrEqual(963);
  });
  it("labels bucketed p95s as bounds", () => {
    expect(callP95({ ...stat, count: 4, avg_ms: 3000 }).text).toBe("under 10s");
    expect(
      callP95({ ...stat, count: 4, avg_ms: 25_000, p95_ms: 40_000 }).text,
    ).toBe("up to 40s");
    expect(
      callP95({ ...stat, count: 4, p95_ms: 3000, p95_bound: false }).text,
    ).toBe("3s");
    expect(
      callP95({ ...stat, count: 4, p95_ms: 120_000, p95_over_max: true }).text,
    ).toBe("over 2m");
  });
});
