// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Finding, SpecialistName } from "./types";
import { SPECIALISTS } from "./types";
import { CHART_VERDICTS, VERDICT_STYLE } from "./verdictStyle";

type ChartVerdict = (typeof CHART_VERDICTS)[number];

/** One radar axis: a specialist, with its confidence on its own verdict's series. */
export interface RadarRow extends Record<ChartVerdict, number> {
  agent: SpecialistName;
  /** Why the specialist contributes nothing, when it does not. */
  note: string | null;
}

/** Confidence runs 0 to 100 (radarRows clamps to it); the radius axis must match. */
export const RADAR_DOMAIN: [number, number] = [0, 100];

function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

/**
 * Radar rows in the fixed specialist order.
 *
 * v2 findings carry one verdict and a 0 to 100 confidence in it, so each
 * specialist puts its confidence on the series of the verdict it reached and 0
 * on the others. A specialist with no usable verdict (no report, a guardrail
 * block, an error, or "unknown", "Error 404" or "Site down") plots 0 everywhere and says why in `note`.
 */
export function radarRows(findings: Finding[]): RadarRow[] {
  return SPECIALISTS.map((agent) => {
    const row: RadarRow = {
      agent,
      note: null,
      phishing: 0,
      suspicious: 0,
      legitimate: 0,
    };
    const finding = findings.find((f) => f.agent === agent);
    if (!finding) return { ...row, note: "No report" };
    if (finding.status === "blocked_by_guardrail")
      return { ...row, note: "Blocked by guardrail" };
    if (finding.status === "error") return { ...row, note: "Specialist error" };
    if (finding.verdict === "unknown") return { ...row, note: "Unknown" };
    if (finding.verdict === "error_404" || finding.verdict === "site_down")
      return { ...row, note: VERDICT_STYLE[finding.verdict].label };
    row[finding.verdict] = clamp(finding.confidence);
    return row;
  });
}

export interface RadarSeries {
  verdict: ChartVerdict;
  /** No specialist reached this verdict, so the series sits at the centre. */
  empty: boolean;
}

/**
 * Every verdict series, always in chart order. Dropping the empty ones made the
 * palette shift between scans (one amber ring here, red and blue there), so the
 * legend and the rings stay fixed and an empty series is only flagged.
 */
export function radarSeries(rows: RadarRow[]): RadarSeries[] {
  return CHART_VERDICTS.map((verdict) => ({
    verdict,
    empty: !rows.some((r) => r[verdict] > 0),
  }));
}
