// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { History } from "lucide-react";
import { Link } from "react-router-dom";
import type { SimilarScan } from "@/lib/types";
import { parseSimilarSummary } from "@/lib/similarScan";
import { RiskPill, VerdictBadge } from "./VerdictBadge";

function SummaryLine({ summary }: { summary: string }) {
  const parsed = parseSimilarSummary(summary);
  if (!parsed) {
    return <span className="break-all font-mono text-xs">{summary}</span>;
  }
  return (
    <div className="min-w-0 space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="break-all font-mono text-xs text-fg">{parsed.url}</span>
        <span data-verdict={parsed.verdict}>
          <VerdictBadge verdict={parsed.verdict} />
        </span>
        {parsed.risk !== null && (
          <span data-risk={parsed.risk} aria-label={`Risk ${parsed.risk} of 100`}>
            <RiskPill score={parsed.risk} />
          </span>
        )}
      </div>
      {parsed.reason && <p className="text-xs text-muted">{parsed.reason}</p>}
    </div>
  );
}

/**
 * Your own earlier scans that episodic memory matched to this one. The API lists only the
 * requesting owner's scans. Summaries are defanged and rendered as plain text.
 */
export function SimilarScans({ scans }: { scans: SimilarScan[] | undefined }) {
  if (!scans?.length) return null;
  return (
    <div className="space-y-2 text-sm text-fg-subtle">
      <p>
        Context the orchestrator saw from earlier scans of similar URLs. It is not
        evidence for this URL; the verdict rests on this scan's findings. This list
        shows only your own scans.
      </p>
      <ul className="divide-y divide-border/60" aria-label="Similar past scans">
        {scans.map((scan) => (
          <li key={scan.scan_id} className="flex items-start gap-2 py-2">
            <History className="mt-0.5 h-4 w-4 shrink-0 text-muted" aria-hidden />
            <SummaryLine summary={scan.summary} />
            <Link
              to={`/results/${encodeURIComponent(scan.scan_id)}`}
              className="ml-auto shrink-0 text-xs text-accent hover:underline"
            >
              Open scan
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
