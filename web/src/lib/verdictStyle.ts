// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Action, ConfidenceBand, VerdictLabel } from "./types";

export type ChartTheme = "light" | "dark";

/**
 * One place for verdict presentation.
 *
 * `token` drives badges and text through the CSS variables in index.css.
 * `chart` holds the fills validated with the dataviz palette validator on
 * 2026-09-29 (light surface #ffffff, dark surface #111626). Red, amber and blue
 * passed every check. The v1 red, amber and emerald set failed protan separation,
 * which is why "legitimate" is blue everywhere in the app.
 */
export const VERDICT_STYLE: Record<
  VerdictLabel,
  {
    label: string;
    token: "danger" | "warn" | "safe" | "neutral";
    chart: Record<ChartTheme, string> | null;
  }
> = {
  phishing: {
    label: "Phishing",
    token: "danger",
    chart: { light: "#d03b3b", dark: "#d03b3b" },
  },
  suspicious: {
    label: "Suspicious",
    token: "warn",
    chart: { light: "#eda100", dark: "#c98500" },
  },
  legitimate: {
    label: "Legitimate",
    token: "safe",
    chart: { light: "#2a78d6", dark: "#3987e5" },
  },
  // Unknown is not a decision, so it is never a chart series; it shows as a tile.
  unknown: { label: "Unknown", token: "neutral", chart: null },
  // The target answered 404, so there was nothing to judge. Neutral like
  // unknown (not red, not blue) and never a chart series, but a distinct label
  // and icon so it is not mistaken for an undecided scan.
  error_404: { label: "Error 404", token: "neutral", chart: null },
  // The target is gone (DNS, refused, 410, dead redirect). Neutral for the same
  // reason as Error 404: a fact about the site, not a judgement of it.
  site_down: { label: "Site down", token: "neutral", chart: null },
};

/** Stack order for verdict charts: most severe at the baseline. */
export const CHART_VERDICTS = ["phishing", "suspicious", "legitimate"] as const;

export function chartColor(
  verdict: (typeof CHART_VERDICTS)[number],
  theme: ChartTheme,
): string {
  const chart = VERDICT_STYLE[verdict].chart;
  if (!chart) throw new Error(`${verdict} has no chart color`);
  return chart[theme];
}

export const CONFIDENCE_STYLE: Record<
  ConfidenceBand,
  { label: string; dots: number }
> = {
  high: { label: "High confidence", dots: 3 },
  medium: { label: "Medium confidence", dots: 2 },
  low: { label: "Low confidence", dots: 1 },
};

export const ACTION_STYLE: Record<
  Action,
  { label: string; token: "danger" | "warn" | "safe" }
> = {
  block: { label: "Block", token: "danger" },
  warn: { label: "Warn", token: "warn" },
  allow: { label: "Allow", token: "safe" },
};

/** Single-series magnitude charts (latency, cost over time). */
export const SEQUENTIAL_COLOR: Record<ChartTheme, string> = {
  light: "#2a78d6",
  dark: "#3987e5",
};

/**
 * Categorical slots for model series. Two slots only: the sample runs two models.
 * A third series must fold into "Other" rather than get a generated hue.
 */
export const MODEL_SERIES: Record<ChartTheme, readonly string[]> = {
  light: ["#2a78d6", "#eb6834"],
  dark: ["#3987e5", "#d95926"],
};

export function seriesColor(index: number, theme: ChartTheme): string {
  const color = MODEL_SERIES[theme][index];
  if (!color)
    throw new Error(`series ${index} has no slot; fold it into "Other"`);
  return color;
}
