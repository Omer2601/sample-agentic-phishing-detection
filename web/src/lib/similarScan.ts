// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { VerdictLabel } from "./types";

export interface SimilarSummary {
  /** Already defanged by the worker (hxxps, [.]), so it is never a live link. */
  url: string;
  verdict: VerdictLabel;
  risk: number | null;
  reason: string | null;
}

const VERDICTS: readonly VerdictLabel[] = [
  "phishing",
  "suspicious",
  "legitimate",
  "unknown",
  "error_404",
  "site_down",
];

function isVerdict(value: string): value is VerdictLabel {
  return (VERDICTS as readonly string[]).includes(value);
}

/**
 * Parses the one-line summary the worker stores in episodic memory
 * (`<defanged url> | verdict=<v> | risk=<n> | reason: <text>`, see
 * backend scan_memory.summarize). Returns null for anything else, so the caller
 * can fall back to showing the stored text as it is.
 */
export function parseSimilarSummary(summary: string): SimilarSummary | null {
  const parts = summary.split(" | ");
  const url = (parts[0] ?? "").trim();
  const verdictPart = parts[1]?.trim() ?? "";
  if (!url || !verdictPart.startsWith("verdict=")) return null;
  const verdict = verdictPart.slice("verdict=".length);
  if (!isVerdict(verdict)) return null;

  let risk: number | null = null;
  let reason: string | null = null;
  for (let i = 2; i < parts.length; i += 1) {
    const part = parts[i].trim();
    if (part.startsWith("reason:")) {
      // The reason is free text and may itself contain the separator.
      reason = parts.slice(i).join(" | ").trim().slice("reason:".length).trim() || null;
      break;
    }
    if (part.startsWith("risk=")) {
      const n = Number(part.slice("risk=".length));
      risk = Number.isInteger(n) && n >= 0 && n <= 100 ? n : null;
    }
  }
  return { url, verdict, risk, reason };
}
