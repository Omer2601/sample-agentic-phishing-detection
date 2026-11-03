// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Tailwind-aware className combiner (shadcn convention). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function clampScore(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

/** Map a numeric risk score to a band (gauge and risk pill colouring). */
export function scoreBand(score: number): "danger" | "warn" | "safe" {
  if (score >= 70) return "danger";
  if (score >= 35) return "warn";
  return "safe";
}

export function formatDuration(seconds: number): string {
  // Round once, up front, then split into units. Rounding the remainder after
  // flooring the minutes printed 119.6 s as "1m 60s".
  const total = Math.round(seconds);
  if (total < 60) return `${total}s`;
  if (total >= 3600) {
    const h = Math.floor(total / 3600);
    const min = Math.floor((total % 3600) / 60);
    return `${h}h ${min.toString().padStart(2, "0")}m`;
  }
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}

export function formatMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "n/a";
  if (Math.round(ms) < 1000) return `${Math.round(ms)} ms`;
  return formatDuration(ms / 1000);
}

/**
 * A p50 or p95 from the backend's latency counters. Past the top bucket it reports
 * 120000 with p95_over_max; otherwise, with `bound`, the value is a bucket upper
 * edge (the counters keep buckets, not durations), so it reads as a bound.
 */
export function formatP95(
  ms: number | null | undefined,
  overMax: boolean | undefined,
  bound?: boolean,
): string {
  if (overMax) return "over 2m";
  if (bound && ms !== null && ms !== undefined) {
    return ms <= FIRST_LATENCY_EDGE_MS ? "under 10s" : `up to ${formatMs(ms)}`;
  }
  return formatMs(ms);
}

/** The first backend latency bucket edge (stats/updates.py LAT_BUCKETS). */
const FIRST_LATENCY_EDGE_MS = 10_000;

/**
 * Costs arrive as decimal strings. Sub-dollar amounts keep four places because a
 * single scan costs cents, and rounding it to "$0.14" hides real differences.
 */
export function formatCost(usd: string | number): string {
  const value = typeof usd === "number" ? usd : Number.parseFloat(usd);
  const safe = Number.isFinite(value) ? value : 0;
  return safe < 1 ? `$${safe.toFixed(4)}` : `$${safe.toFixed(2)}`;
}

export function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

export function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

/** Normalise user input into a candidate URL for validation and submission. */
export function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "";
  // Keep any explicit scheme so validateUrl can reject ftp: and friends by name.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

/**
 * Client-side sanity check only. The backend's validation and SSRF guard are
 * authoritative; this catches obvious typos before a 30 second scan starts.
 */
export function validateUrl(input: string): string | null {
  const candidate = normalizeUrl(input);
  if (!candidate) return "Enter a URL to scan.";
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return "That doesn't look like a valid URL.";
  }
  if (!/^https?:$/.test(parsed.protocol))
    return "Only http and https URLs can be scanned.";
  if (!parsed.hostname.includes("."))
    return "Enter a fully-qualified hostname (e.g. example.com).";
  return null;
}
