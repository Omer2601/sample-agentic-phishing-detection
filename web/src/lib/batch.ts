// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { BatchRecord } from "./types";

/**
 * How long a batch may wait for its CSV before the UI stops treating it as
 * running. The backend marks such batches FAILED ("CSV was never uploaded") on
 * its own schedule; this keeps the UI from polling one forever in the meantime.
 */
export const UPLOAD_WAIT_MS = 15 * 60_000;

/**
 * The backend stamps completed_at when the last URL reaches a terminal state,
 * and also when it closes a batch with an error (a CSV that could not be split,
 * or one that never arrived). Either stops polling at once; the error check
 * does not wait for completed_at. An upload still outstanding past the life of
 * its presigned POST is not going to arrive either.
 */
export function isBatchActive(b: BatchRecord, nowMs: number = Date.now()): boolean {
  if (b.completed_at !== null || b.error) return false;
  if (b.awaiting_upload && nowMs - Date.parse(b.created_at) > UPLOAD_WAIT_MS) {
    return false;
  }
  return true;
}

export function batchCounts(b: BatchRecord) {
  const complete = b.status_counts.COMPLETE ?? 0;
  const failed = b.status_counts.FAILED ?? 0;
  const done = complete + failed;
  return {
    total: b.total,
    complete,
    failed,
    pending: Math.max(0, b.total - done),
    done,
  };
}

export function batchElapsedMs(b: BatchRecord, nowMs: number): number {
  if (!isBatchActive(b, nowMs) && b.wall_clock_ms !== null) return b.wall_clock_ms;
  return Math.max(0, nowMs - Date.parse(b.created_at));
}

/** Remaining time at the throughput observed so far; null until something finishes. */
export function estimateEtaMs(b: BatchRecord, nowMs: number): number | null {
  const { done, pending } = batchCounts(b);
  if (!isBatchActive(b, nowMs) || done === 0 || !b.first_started_at) return null;
  const since = nowMs - Date.parse(b.first_started_at);
  return Math.round((since / done) * pending);
}
