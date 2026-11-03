// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/** Copy and helpers for the report states of the result page (kept out of the component file for fast refresh). */
export const REPORT_PENDING_TITLE = "Writing the full report";
export const REPORT_PENDING_TEXT =
  "The verdict above is ready. The detailed report usually takes under a minute more.";
export const REPORT_FAILED_TEXT =
  "The full report could not be generated. The verdict above is still valid.";
export const REPORT_TIMEOUT_TEXT =
  "The report is taking longer than expected. The verdict above is still valid.";
export const REPORT_WAIT_HINT = "Available when the report is ready";

/** Seconds since `startedAt`, never negative (clock skew) and 0 when unparseable. */
export function elapsedSecondsSince(
  startedAt: string | null | undefined,
  nowMs: number,
  fallbackMs: number,
): number {
  const parsed = startedAt ? Date.parse(startedAt) : Number.NaN;
  const from = Number.isFinite(parsed) ? parsed : fallbackMs;
  return Math.max(0, Math.floor((nowMs - from) / 1000));
}
