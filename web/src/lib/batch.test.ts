// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import type { BatchRecord } from "./types";
import {
  batchCounts,
  batchElapsedMs,
  estimateEtaMs,
  isBatchActive,
} from "./batch";

const T0 = Date.parse("2026-09-29T12:00:00Z");

function batch(overrides: Partial<BatchRecord> = {}): BatchRecord {
  return {
    batch_id: "b-1",
    source: "ui",
    total: 200,
    status_counts: { COMPLETE: 45, FAILED: 5, RUNNING: 25, PENDING: 125 },
    verdict_counts: { phishing: 30 },
    created_at: "2026-09-29T12:00:00Z",
    first_started_at: "2026-09-29T12:00:10Z",
    completed_at: null,
    wall_clock_ms: null,
    sum_scan_ms: 0,
    cost_usd: "3.10",
    awaiting_upload: false,
    split_at: null,
    error: null,
    ...overrides,
  };
}

describe("batch math", () => {
  it("is active until the backend stamps completed_at", () => {
    expect(isBatchActive(batch())).toBe(true);
    expect(isBatchActive(batch({ completed_at: "2026-09-29T12:05:00Z" }))).toBe(
      false,
    );
  });

  it("is not active once the batch carries an error", () => {
    expect(isBatchActive(batch({ error: "CSV was never uploaded" }), T0)).toBe(
      false,
    );
  });

  it("stops treating an upload that never arrived as active after 15 minutes", () => {
    const waiting = batch({ awaiting_upload: true, total: 0, status_counts: {} });
    expect(isBatchActive(waiting, T0 + 14 * 60_000)).toBe(true);
    expect(isBatchActive(waiting, T0 + 15 * 60_000 + 1)).toBe(false);
  });

  it("stops at once for an abandoned upload as GET /batches returns it", () => {
    // backend store.mark_batch_error: error, completed_at and split_at set,
    // awaiting_upload cleared, total zeroed (test_api.py lifecycle test).
    const abandoned = batch({
      total: 0,
      status_counts: {},
      first_started_at: null,
      completed_at: "2026-09-29T12:30:00Z",
      wall_clock_ms: 0,
      split_at: "2026-09-29T12:30:00Z",
      awaiting_upload: false,
      error: "CSV was never uploaded",
    });
    expect(isBatchActive(abandoned, T0 + 60_000)).toBe(false);
  });

  it("keeps a fresh upload that is still awaiting its CSV active", () => {
    const waiting = batch({ awaiting_upload: true, total: 0, status_counts: {} });
    expect(isBatchActive(waiting, T0 + 60_000)).toBe(true);
  });

  it("counts done and pending from the total", () => {
    expect(batchCounts(batch())).toEqual({
      total: 200,
      complete: 45,
      failed: 5,
      pending: 150,
      done: 50,
    });
  });

  it("uses live elapsed time while running and wall clock when done", () => {
    expect(batchElapsedMs(batch(), T0 + 90_000)).toBe(90_000);
    expect(
      batchElapsedMs(
        batch({ completed_at: "2026-09-29T12:05:00Z", wall_clock_ms: 300_000 }),
        T0 + 999_999,
      ),
    ).toBe(300_000);
  });

  it("projects remaining time from the observed throughput", () => {
    // 50 done in 100 s since the first start, 150 left: 300 s.
    expect(estimateEtaMs(batch(), T0 + 110_000)).toBe(300_000);
  });

  it("has no estimate before anything finishes or after completion", () => {
    expect(
      estimateEtaMs(batch({ status_counts: { PENDING: 200 } }), T0 + 10_000),
    ).toBeNull();
    expect(
      estimateEtaMs(batch({ completed_at: "2026-09-29T12:05:00Z" }), T0),
    ).toBeNull();
  });
});
