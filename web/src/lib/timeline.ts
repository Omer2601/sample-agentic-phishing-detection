// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Call, CallKind, ScanRecord, SpecialistName } from "./types";
import { SPECIALISTS } from "./types";

export interface TimelineRow {
  key: string;
  label: string;
  kind: CallKind;
  /** 0 harness (and its registry lookup), 1 specialist, 2 tool or model call inside a specialist. */
  depth: 0 | 1 | 2;
  offsetMs: number;
  durationMs: number;
  status: Call["status"];
  /** The specialist a run or sub-call belongs to; null for the harness and orphans. */
  owner: SpecialistName | null;
}

const DEPTH: Record<CallKind, 0 | 1 | 2> = {
  harness: 0,
  specialist: 1,
  model: 2,
  browser: 2,
  whois: 2,
  web_search: 2,
  // A harness-level Gateway call with no specialist owner: shown with the harness rows so
  // it never adopts orphan sub-calls the way a specialist run does.
  registry: 0,
};

const KIND_WORD: Record<CallKind, string> = {
  harness: "harness",
  specialist: "run",
  model: "model",
  browser: "browser",
  whois: "WHOIS",
  web_search: "web search",
  registry: "registry",
};

const isSpecialist = (name: string) =>
  (SPECIALISTS as readonly string[]).includes(name);

/**
 * The worker names a specialist run after the agent, and each specialist names its
 * own model, browser and web search calls after itself too, so a bare name listed
 * one agent up to four times. A run reads "url_analyst (run)"; a sub-call named
 * after its agent reads "brand_visual browser"; a sub-call with its own name
 * (whois_lookup, a model id) keeps it.
 */
export function callLabel(c: Pick<Call, "kind" | "name">): string {
  if (c.kind === "specialist") return `${c.name} (run)`;
  if (DEPTH[c.kind] === 2 && isSpecialist(c.name))
    return `${c.name} ${KIND_WORD[c.kind]}`;
  return c.name;
}

/**
 * A dispatcher error Finding (and scans stored before 2026-10-16) can hold two
 * overlapping specialist calls for one agent: the same run timed from two layers.
 * Keep the outer (earliest, longest).
 */
function mergeSpecialistRuns(calls: Call[]): Call[] {
  const kept: Call[] = [];
  const spans = new Map<Call, [number, number]>();
  const span = (c: Call): [number, number] => {
    const s = Date.parse(c.started_at);
    return [s, s + c.duration_ms];
  };
  const ordered = [...calls].sort(
    (a, b) => span(a)[0] - span(b)[0] || b.duration_ms - a.duration_ms,
  );
  const position = new Map(calls.map((c, i) => [c, i]));
  for (const c of ordered) {
    if (c.kind !== "specialist") {
      kept.push(c);
      continue;
    }
    const [s, e] = span(c);
    const outer = kept.find((k) => {
      if (k.kind !== "specialist" || k.name !== c.name) return false;
      const [ks, ke] = spans.get(k)!;
      return s < ke && ks < e;
    });
    if (outer) {
      const [ks, ke] = spans.get(outer)!;
      spans.set(outer, [Math.min(ks, s), Math.max(ke, e)]);
      continue;
    }
    spans.set(c, [s, e]);
    kept.push(c);
  }
  kept.sort((a, b) => position.get(a)! - position.get(b)!);
  return kept.map((c) => {
    const merged = spans.get(c);
    if (!merged) return c;
    return {
      ...c,
      started_at: new Date(merged[0]).toISOString(),
      duration_ms: merged[1] - merged[0],
    };
  });
}

/**
 * A Call has no id in phish_contracts (models.py Call: kind, name, started_at,
 * duration_ms, status, usage), so its identity is those timed fields. The start
 * is compared as epoch ms so "Z" and "+00:00" spellings of one instant match.
 */
function callKey(c: Call): string {
  return [c.kind, c.name, Date.parse(c.started_at), c.duration_ms, c.status].join("|");
}

/**
 * Flatten the worker-timed calls (harness, specialists) and each specialist's own
 * calls (browser, WHOIS, model) into one waterfall. Offsets are relative to the
 * earliest start so the chart reads from zero.
 */
export function buildTimeline(record: Pick<ScanRecord, "calls" | "findings">): {
  rows: TimelineRow[];
  totalMs: number;
} {
  // The worker also copies each specialist's own calls into record.calls, so a
  // finding call already listed there is the same call, not a second one. Counts,
  // not a set: two real calls that happen to share every field stay two rows.
  const listed = new Map<string, number>();
  for (const c of record.calls) {
    const k = callKey(c);
    listed.set(k, (listed.get(k) ?? 0) + 1);
  }
  const fromFindings = record.findings
    .flatMap((f) => f.calls)
    .filter((c) => {
      const k = callKey(c);
      const n = listed.get(k) ?? 0;
      if (n === 0) return true;
      listed.set(k, n - 1);
      return false;
    });
  const all: Call[] = mergeSpecialistRuns([...record.calls, ...fromFindings]);
  if (all.length === 0) return { rows: [], totalMs: 0 };
  // Who made each sub-call: the finding that reported it, else a sub-call named
  // after its agent (the worker's copy of a finding call).
  const reportedBy = new Map<string, SpecialistName>();
  for (const f of record.findings)
    for (const c of f.calls) reportedBy.set(callKey(c), f.agent);
  const ownerOf = (c: Call): SpecialistName | null => {
    if (c.kind === "harness") return null;
    if (c.kind === "specialist" || isSpecialist(c.name))
      return isSpecialist(c.name) ? (c.name as SpecialistName) : null;
    return reportedBy.get(callKey(c)) ?? null;
  };
  const starts = all.map((c) => Date.parse(c.started_at));
  const t0 = Math.min(...starts);
  const byStart = (a: TimelineRow, b: TimelineRow) =>
    a.offsetMs - b.offsetMs || a.depth - b.depth;
  const flat: TimelineRow[] = all
    .map((c, i) => ({
      key: `${c.kind}-${c.name}-${i}`,
      label: callLabel(c),
      kind: c.kind,
      depth: DEPTH[c.kind],
      offsetMs: starts[i] - t0,
      durationMs: c.duration_ms,
      status: c.status,
      owner: ownerOf(c),
    }))
    .sort(byStart);
  // Nest: each specialist run is followed by its own sub-calls, so a reader scans
  // one agent at a time. Sub-calls whose run was not timed follow in start order.
  const runs = flat.filter((r) => r.depth === 1);
  const placed = new Set<TimelineRow>();
  const rows: TimelineRow[] = [];
  for (const r of flat.filter((r) => r.depth === 0)) {
    rows.push(r);
    placed.add(r);
  }
  for (const run of runs) {
    rows.push(run);
    placed.add(run);
    const isFirstRun = runs.find((x) => x.owner === run.owner) === run;
    if (!isFirstRun) continue;
    for (const sub of flat)
      if (sub.depth === 2 && sub.owner === run.owner && !placed.has(sub)) {
        rows.push(sub);
        placed.add(sub);
      }
  }
  for (const r of flat) if (!placed.has(r)) rows.push(r);
  const totalMs = Math.max(...rows.map((r) => r.offsetMs + r.durationMs));
  return { rows, totalMs };
}

export function scanTokens(record: Pick<ScanRecord, "calls" | "findings">): {
  input: number;
  output: number;
} {
  const usages = [
    ...record.calls.flatMap((c) =>
      c.kind === "harness" && c.usage ? [c.usage] : [],
    ),
    ...record.findings.map((f) => f.usage),
  ];
  return {
    input: usages.reduce((n, u) => n + u.input_tokens, 0),
    output: usages.reduce((n, u) => n + u.output_tokens, 0),
  };
}
