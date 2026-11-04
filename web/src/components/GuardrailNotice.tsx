// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { ShieldAlert } from "lucide-react";

const TEXT: Record<string, string> = {
  input_guardrail_intervened:
    "The input guardrail flagged this URL. It was still scanned; treat the flag as a signal.",
  output_guardrail_intervened:
    "The output guardrail withheld part of the report. The verdict is unchanged.",
  guardrail_unavailable:
    "A guardrail check could not run for this scan; the scan itself completed normally.",
};

/** Guardrail interventions are evidence on the scan, never a reason it was dropped. */
export function GuardrailNotice({ events }: { events: string[] }) {
  if (!events.length) return null;
  return (
    <ul
      className="space-y-1 rounded-xl border border-warn/40 bg-warn/5 px-4 py-3 text-sm text-fg-subtle animate-fade-in"
      aria-label="Guardrail notes"
    >
      {events.map((e) => (
        <li key={e} className="flex items-start gap-2">
          <ShieldAlert
            className="mt-0.5 h-4 w-4 shrink-0 text-warn"
            aria-hidden
          />
          <span>{TEXT[e] ?? e}</span>
        </li>
      ))}
    </ul>
  );
}
