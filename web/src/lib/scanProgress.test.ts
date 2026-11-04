// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import type { ScanRecord } from "./types";
import { deriveProgress, isTerminal, stageIndex } from "./scanProgress";

const T0 = Date.parse("2026-09-29T12:00:00Z");

function scan(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    scan_id: "s-1",
    url: "https://a.example",
    batch_id: null,
    status: "RUNNING",
    queued_at: "2026-09-29T11:59:58Z",
    started_at: "2026-09-29T12:00:00Z",
    completed_at: null,
    queue_wait_ms: 2000,
    total_ms: null,
    verdict: null,
    findings: [],
    calls: [],
    cost_usd: "0",
    error: null,
    attempts: 0,
    guardrail_events: [],
    ...overrides,
  };
}

describe("deriveProgress", () => {
  it("reports queued while pending", () => {
    const p = deriveProgress(scan({ status: "PENDING", started_at: null }), T0);
    expect(p.stage).toBe("QUEUED");
    expect(p.progress).toBe(0);
  });

  it("reports specialists early in the run", () => {
    const p = deriveProgress(scan(), T0 + 10_000);
    expect(p.stage).toBe("SPECIALISTS");
    expect(p.elapsedSeconds).toBe(10);
  });

  it("reports the verdict stage after the specialist budget", () => {
    expect(deriveProgress(scan(), T0 + 30_000).stage).toBe("VERDICT");
  });

  it("never claims completion before the API does", () => {
    expect(deriveProgress(scan(), T0 + 600_000).progress).toBe(0.95);
  });

  it("is done when complete", () => {
    const p = deriveProgress(
      scan({ status: "COMPLETE", total_ms: 34_000 }),
      T0,
    );
    expect(p).toMatchObject({ stage: "DONE", progress: 1, elapsedSeconds: 34 });
  });

  it("knows terminal states and stage order", () => {
    expect(isTerminal("FAILED")).toBe(true);
    expect(isTerminal("RUNNING")).toBe(false);
    expect(stageIndex("VERDICT")).toBe(2);
  });
});
