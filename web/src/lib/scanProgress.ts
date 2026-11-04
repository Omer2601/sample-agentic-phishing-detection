// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type {
  ReportStatus,
  ScanProgress,
  ScanRecord,
  ScanStage,
  ScanStatus,
} from "./types";

export interface StageInfo {
  stage: ScanStage;
  label: string;
  description: string;
}

/** Target from the spec: 30 to 40 s per URL. Used only for the progress estimate. */
export const TYPICAL_SCAN_SECONDS = 35;
/** The three specialists run in parallel; the orchestrator verdict follows. */
const SPECIALIST_BUDGET_SECONDS = 25;

export const STAGE_SEQUENCE: StageInfo[] = [
  {
    stage: "QUEUED",
    label: "Queued",
    description: "Accepted, waiting for a worker",
  },
  {
    stage: "SPECIALISTS",
    label: "Specialists",
    description: "URL, brand and visual, and code analysts run in parallel",
  },
  {
    stage: "VERDICT",
    label: "Verdict",
    description: "Orchestrator weighs the findings and writes the report",
  },
  { stage: "DONE", label: "Complete", description: "Verdict ready" },
];

export function stageIndex(stage: ScanStage): number {
  return STAGE_SEQUENCE.findIndex((s) => s.stage === stage);
}

export function isTerminal(status: ScanStatus): boolean {
  return status === "COMPLETE" || status === "FAILED";
}

/**
 * Presentational only: the API reports PENDING, RUNNING or terminal, so the stage
 * inside RUNNING is estimated from elapsed time. The verdict never depends on it.
 */
export function deriveProgress(
  record: ScanRecord,
  nowMs: number,
): ScanProgress {
  const base = { scanId: record.scan_id, status: record.status };
  if (isTerminal(record.status)) {
    return {
      ...base,
      stage: "DONE",
      progress: 1,
      elapsedSeconds: Math.round((record.total_ms ?? 0) / 1000),
    };
  }
  if (record.status === "PENDING" || !record.started_at) {
    return { ...base, stage: "QUEUED", progress: 0, elapsedSeconds: 0 };
  }
  const elapsedSeconds = Math.max(
    0,
    Math.round((nowMs - Date.parse(record.started_at)) / 1000),
  );
  return {
    ...base,
    stage:
      elapsedSeconds < SPECIALIST_BUDGET_SECONDS ? "SPECIALISTS" : "VERDICT",
    progress: Math.min(0.95, elapsedSeconds / TYPICAL_SCAN_SECONDS),
    elapsedSeconds,
  };
}

/** The effective report state of a record; a missing field means READY (older records). */
export function reportStatusOf(
  record: Pick<ScanRecord, "report_status">,
): ReportStatus {
  return record.report_status ?? "READY";
}

/** The verdict is shown but the full report is still being written. */
export function isReportPending(
  record: Pick<ScanRecord, "status" | "report_status">,
): boolean {
  return record.status === "COMPLETE" && reportStatusOf(record) === "PENDING";
}
