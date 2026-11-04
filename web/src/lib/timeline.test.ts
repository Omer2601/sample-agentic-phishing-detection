// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import type { Call, Finding, ScanRecord } from "./types";
import { buildTimeline, scanTokens } from "./timeline";

const call = (
  kind: Call["kind"],
  name: string,
  startS: number,
  ms: number,
  status: Call["status"] = "ok",
): Call => ({
  kind,
  name,
  started_at: new Date(
    Date.parse("2026-09-29T12:00:00Z") + startS * 1000,
  ).toISOString(),
  duration_ms: ms,
  status,
});

const finding = (
  agent: Finding["agent"],
  calls: Call[],
  tokens: [number, number],
): Finding => ({
  agent,
  status: "ok",
  verdict: "phishing",
  confidence: 90,
  signals: [],
  artifacts: [],
  usage: {
    input_tokens: tokens[0],
    output_tokens: tokens[1],
    model_id: "global.anthropic.claude-sonnet-5-5",
  },
  latency_ms: 0,
  calls,
});

const record = {
  scan_id: "s",
  started_at: "2026-09-29T12:00:00Z",
  calls: [
    {
      ...call("harness", "phish_orchestrator", 0, 34_000),
      usage: {
        input_tokens: 1000,
        output_tokens: 500,
        model_id: "us.anthropic.claude-opus-5-5",
      },
    },
    call("specialist", "brand_visual", 2, 21_000),
    call("specialist", "url_analyst", 2, 9_000),
  ],
  findings: [
    finding(
      "brand_visual",
      [call("browser", "navigate_and_screenshot", 3, 12_000)],
      [300, 80],
    ),
    finding(
      "url_analyst",
      [call("whois", "whois_lookup", 2.5, 800, "error")],
      [200, 40],
    ),
  ],
} as unknown as ScanRecord;

describe("buildTimeline", () => {
  it("orders rows by start and nests tool calls under their agent", () => {
    const { rows, totalMs } = buildTimeline(record);
    expect(rows.map((r) => [r.label, r.depth, r.owner])).toEqual([
      ["phish_orchestrator", 0, null],
      ["brand_visual (run)", 1, "brand_visual"],
      ["navigate_and_screenshot", 2, "brand_visual"],
      ["url_analyst (run)", 1, "url_analyst"],
      ["whois_lookup", 2, "url_analyst"],
    ]);
    expect(rows[4]).toMatchObject({
      offsetMs: 2500,
      durationMs: 800,
      status: "error",
    });
    expect(totalMs).toBe(34_000);
  });

  it("counts a call once when the worker copied it from a finding into record.calls", () => {
    // The UI e2e run 2 shape (scan 5a79db5d): the worker now lists each
    // specialist's own calls in record.calls as well, so a plain concat of
    // record.calls and findings[].calls showed 16 calls for the API's 10.
    const innerModel = call("model", "global.anthropic.claude-sonnet-5-5", 4, 6_000);
    const findings = [
      finding(
        "brand_visual",
        [call("browser", "navigate_and_screenshot", 3, 12_000), innerModel],
        [300, 80],
      ),
      finding(
        "url_analyst",
        [call("whois", "whois_lookup", 2.5, 800, "error")],
        [200, 40],
      ),
    ];
    const worker = [
      ...record.calls,
      ...findings.flatMap((f) => f.calls.map((c) => ({ ...c }))),
    ];
    const { rows } = buildTimeline({ calls: worker, findings });
    expect(rows).toHaveLength(6);
    expect(rows.map((r) => r.label).sort()).toEqual(
      [
        "brand_visual (run)",
        "global.anthropic.claude-sonnet-5-5",
        "navigate_and_screenshot",
        "phish_orchestrator",
        "url_analyst (run)",
        "whois_lookup",
      ].sort(),
    );
    expect(new Set(rows.map((r) => r.key)).size).toBe(rows.length);
  });

  it("keeps two genuinely separate calls with the same name", () => {
    const retry = [
      call("model", "m", 3, 1_000, "blocked_by_guardrail"),
      call("model", "m", 4, 1_000),
    ];
    const { rows } = buildTimeline({
      calls: [],
      findings: [finding("url_analyst", retry, [1, 1])],
    });
    expect(rows).toHaveLength(2);
  });

  it("returns an empty timeline when nothing was recorded", () => {
    expect(buildTimeline({ ...record, calls: [], findings: [] })).toEqual({
      rows: [],
      totalMs: 0,
    });
  });
});

describe("buildTimeline labels", () => {
  // A live scan shape: the worker times each specialist as a Gateway tool call
  // (kind specialist), and each specialist reports its own model, browser and
  // web search calls under its own agent name, so all of them were labelled
  // "brand_visual" and the specialist appeared four times.
  const scan = {
    calls: [
      call("harness", "phish_orchestrator", 0, 34_000),
      call("specialist", "url_analyst", 2, 9_000),
      call("specialist", "brand_visual", 2, 21_000),
    ],
    findings: [
      finding(
        "url_analyst",
        [
          call("whois", "whois_lookup", 2.5, 800),
          call("model", "url_analyst", 3.5, 6_000),
        ],
        [1, 1],
      ),
      finding(
        "brand_visual",
        [
          call("browser", "brand_visual", 3, 8_000),
          call("web_search", "brand_visual", 11, 1_500),
          call("model", "brand_visual", 12.5, 9_000),
        ],
        [1, 1],
      ),
    ],
  };

  it("names each specialist once at the top level and labels its sub-calls by kind", () => {
    const { rows } = buildTimeline(scan);
    const top = rows.filter((r) => r.depth <= 1).map((r) => r.label).sort();
    expect(top).toEqual(["brand_visual (run)", "phish_orchestrator", "url_analyst (run)"]);
    expect(new Set(rows.map((r) => r.label)).size).toBe(rows.length);
    const sub = rows.filter((r) => r.depth === 2).map((r) => r.label).sort();
    expect(sub).toEqual(
      [
        "whois_lookup",
        "url_analyst model",
        "brand_visual browser",
        "brand_visual web search",
        "brand_visual model",
      ].sort(),
    );
    // Each run is followed by its own sub-calls, in start order.
    expect(rows.map((r) => r.label)).toEqual([
      "phish_orchestrator",
      "url_analyst (run)",
      "whois_lookup",
      "url_analyst model",
      "brand_visual (run)",
      "brand_visual browser",
      "brand_visual web search",
      "brand_visual model",
    ]);
    for (const name of ["url_analyst", "brand_visual"]) {
      expect(rows.filter((r) => r.label === name)).toHaveLength(0);
    }
  });

  it("merges an older two-layer specialist call that overlaps the harness call for the same agent", () => {
    const { rows } = buildTimeline({
      calls: scan.calls,
      findings: [
        finding(
          "url_analyst",
          [call("specialist", "url_analyst", 2.2, 8_500), call("whois", "whois_lookup", 2.5, 800)],
          [1, 1],
        ),
      ],
    });
    expect(rows.filter((r) => r.label === "url_analyst (run)")).toHaveLength(1);
    expect(rows.find((r) => r.label === "url_analyst (run)")).toMatchObject({
      offsetMs: 2_000,
      durationMs: 9_000,
    });
  });

  it("keeps two separate runs of one specialist that do not overlap", () => {
    const { rows } = buildTimeline({
      calls: [call("specialist", "code_analyst", 0, 1_000), call("specialist", "code_analyst", 5, 1_000)],
      findings: [],
    });
    expect(rows.filter((r) => r.label === "code_analyst (run)")).toHaveLength(2);
  });
});

describe("scanTokens", () => {
  it("sums orchestrator and specialist usage", () => {
    expect(scanTokens(record)).toEqual({ input: 1500, output: 620 });
  });
});
