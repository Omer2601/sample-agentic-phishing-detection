// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describeSignal } from "@/lib/signals";
import type { Finding, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";
import { Clamp } from "./ui";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-danger/15 text-danger",
  high: "bg-danger/10 text-danger",
  medium: "bg-warn/15 text-warn",
  low: "bg-surface-2 text-fg-subtle",
};

/**
 * A specialist's signals, most severe first: the analyst-facing title from the
 * signal catalog, its plain explanation as visible text (no tooltip), then the
 * evidence. Evidence is plain text, never markup.
 */
export function SignalList({ finding }: { finding?: Finding }) {
  if (!finding || finding.signals.length === 0) {
    return <p className="text-sm text-muted">No signals recorded.</p>;
  }
  const signals = [...finding.signals].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  return (
    <ul className="space-y-3">
      {signals.map((s, i) => {
        const copy = describeSignal(s.name);
        return (
        <li key={`${s.name}-${i}`} className="space-y-1">
          <div className="flex items-start gap-2">
            <span
              className={cn(
                "mt-0.5 shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                SEVERITY_CLASS[s.severity],
              )}
            >
              {s.severity}
            </span>
            <span className="min-w-0 text-sm font-medium text-fg">{copy.title}</span>
          </div>
          {copy.explain && (
            <p className="text-xs leading-relaxed text-muted">{copy.explain}</p>
          )}
          <Clamp lines={4}>
            <span className="whitespace-pre-line text-sm leading-relaxed text-fg-subtle">
              {s.evidence}
            </span>
          </Clamp>
        </li>
        );
      })}
    </ul>
  );
}
