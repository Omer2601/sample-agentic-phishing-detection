// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";
import type { BatchRecord } from "@/lib/types";

const listBatches = vi.fn();
vi.mock("@/lib/api", () => ({
  api: { listBatches: (...a: unknown[]) => listBatches(...a) },
}));

import {
  ActiveBatchesProvider,
  BATCH_POLL_MS,
  useActiveBatches,
} from "./useActiveBatches";

function record(id: string, done: boolean): BatchRecord {
  return {
    batch_id: id,
    source: "ui",
    total: 2,
    status_counts: done ? { COMPLETE: 2 } : { RUNNING: 2 },
    verdict_counts: {},
    created_at: "2026-09-29T12:00:00Z",
    first_started_at: null,
    completed_at: done ? "2026-09-29T12:01:00Z" : null,
    wall_clock_ms: done ? 60_000 : null,
    sum_scan_ms: 0,
    cost_usd: "0",
    awaiting_upload: false,
    split_at: null,
    error: null,
  };
}

function Probe() {
  const { batches, active } = useActiveBatches();
  return <p>{`${batches.length} batches, ${active.length} active`}</p>;
}

beforeEach(() => {
  vi.useFakeTimers();
  listBatches.mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("ActiveBatchesProvider", () => {
  it("restores batches from the server on mount", async () => {
    listBatches.mockResolvedValue({ items: [record("a", true)], next: null });
    render(
      <ActiveBatchesProvider>
        <Probe />
      </ActiveBatchesProvider>,
    );
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.getByText("1 batches, 0 active")).toBeTruthy();
  });

  it("polls every 2 s while a batch runs and stops when it finishes", async () => {
    listBatches
      .mockResolvedValueOnce({ items: [record("a", false)], next: null })
      .mockResolvedValue({ items: [record("a", true)], next: null });
    render(
      <ActiveBatchesProvider>
        <Probe />
      </ActiveBatchesProvider>,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(BATCH_POLL_MS * 3);
    });
    const calls = listBatches.mock.calls.length;
    expect(screen.getByText("1 batches, 0 active")).toBeTruthy();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(BATCH_POLL_MS * 5);
    });
    expect(listBatches.mock.calls.length).toBe(calls);
  });

  it("fails loudly outside the provider", () => {
    // jsdom has no reportError; React logs the thrown render error via console.error.
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<Probe />)).toThrow(/ActiveBatchesProvider/);
    spy.mockRestore();
  });

  it("stops polling as soon as a waiting upload comes back failed", async () => {
    const waiting: BatchRecord = {
      ...record("u", false),
      total: 0,
      status_counts: {},
      created_at: new Date().toISOString(),
      awaiting_upload: true,
    };
    const failed: BatchRecord = {
      ...waiting,
      awaiting_upload: false,
      completed_at: new Date().toISOString(),
      split_at: new Date().toISOString(),
      wall_clock_ms: 0,
      error: "CSV was never uploaded",
    };
    // Mount load and the first poll tick both see the waiting upload; the next
    // poll sees the sweeper's failure.
    listBatches
      .mockResolvedValueOnce({ items: [waiting], next: null })
      .mockResolvedValueOnce({ items: [waiting], next: null })
      .mockResolvedValue({ items: [failed], next: null });
    render(
      <ActiveBatchesProvider>
        <Probe />
      </ActiveBatchesProvider>,
    );
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.getByText("1 batches, 1 active")).toBeTruthy();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(BATCH_POLL_MS);
    });
    expect(screen.getByText("1 batches, 0 active")).toBeTruthy();
    const calls = listBatches.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(BATCH_POLL_MS * 5);
    });
    expect(listBatches.mock.calls.length).toBe(calls);
  });
});
