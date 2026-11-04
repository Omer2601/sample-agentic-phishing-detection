// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import type { Finding } from "./types";
import { radarRows, radarSeries } from "./specialistRadar";

const usage = { input_tokens: 1, output_tokens: 1, model_id: "m" };
function finding(over: Partial<Finding>): Finding {
  return {
    agent: "url_analyst",
    status: "ok",
    verdict: "phishing",
    confidence: 90,
    signals: [],
    artifacts: [],
    usage,
    latency_ms: 1200,
    calls: [],
    ...over,
  };
}

describe("radarRows", () => {
  it("puts each specialist's confidence on the axis of its own verdict only", () => {
    const rows = radarRows([
      finding({ agent: "url_analyst", verdict: "phishing", confidence: 92 }),
      finding({ agent: "brand_visual", verdict: "legitimate", confidence: 70 }),
      finding({ agent: "code_analyst", verdict: "suspicious", confidence: 55 }),
    ]);
    expect(rows.map((r) => r.agent)).toEqual([
      "url_analyst",
      "brand_visual",
      "code_analyst",
    ]);
    expect(rows[0]).toMatchObject({ phishing: 92, suspicious: 0, legitimate: 0 });
    expect(rows[1]).toMatchObject({ phishing: 0, suspicious: 0, legitimate: 70 });
    expect(rows[2]).toMatchObject({ phishing: 0, suspicious: 55, legitimate: 0 });
  });

  it("plots zero for a specialist that did not report, was blocked, errored or said unknown", () => {
    const rows = radarRows([
      finding({ agent: "brand_visual", status: "blocked_by_guardrail", confidence: 80 }),
      finding({ agent: "code_analyst", verdict: "unknown", confidence: 40 }),
    ]);
    for (const row of rows) {
      expect(row.phishing + row.suspicious + row.legitimate).toBe(0);
    }
    expect(rows.map((r) => r.note)).toEqual([
      "No report",
      "Blocked by guardrail",
      "Unknown",
    ]);
  });

  it("notes an Error 404 specialist as Error 404, not Unknown", () => {
    const rows = radarRows([
      finding({ agent: "url_analyst", verdict: "error_404", confidence: 90 }),
    ]);
    expect(rows[0].note).toBe("Error 404");
    expect(rows[0].phishing + rows[0].suspicious + rows[0].legitimate).toBe(0);
  });

  it("notes a Site down specialist as Site down", () => {
    const rows = radarRows([
      finding({ agent: "url_analyst", verdict: "site_down", confidence: 90 }),
    ]);
    expect(rows[0].note).toBe("Site down");
    expect(rows[0].phishing + rows[0].suspicious + rows[0].legitimate).toBe(0);
  });

  it("clamps a confidence outside 0 to 100", () => {
    const rows = radarRows([finding({ confidence: 140 })]);
    expect(rows[0].phishing).toBe(100);
  });
});

describe("radarSeries", () => {
  it("always lists all three verdicts in the fixed chart order, flagging the empty ones", () => {
    const rows = radarRows([
      finding({ agent: "url_analyst", verdict: "legitimate", confidence: 60 }),
      finding({ agent: "code_analyst", verdict: "phishing", confidence: 80 }),
    ]);
    expect(radarSeries(rows)).toEqual([
      { verdict: "phishing", empty: false },
      { verdict: "suspicious", empty: true },
      { verdict: "legitimate", empty: false },
    ]);
  });

  it("keeps all three series, all empty, when no specialist reached a verdict", () => {
    const series = radarSeries(radarRows([]));
    expect(series.map((s) => s.verdict)).toEqual(["phishing", "suspicious", "legitimate"]);
    expect(series.every((s) => s.empty)).toBe(true);
  });
});
