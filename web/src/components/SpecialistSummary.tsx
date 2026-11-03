// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useId } from "react";
import { AlertTriangle, Clock, ShieldOff } from "lucide-react";
import type { Finding, SpecialistName, Verdict } from "@/lib/types";
import { SPECIALISTS } from "@/lib/types";
import { formatMs } from "@/lib/utils";
import { SignalList } from "./SignalList";
import { SPECIALIST_VISUAL } from "./specialistVisual";
import { VerdictBadge } from "./VerdictBadge";
import { Badge, Card, CardBody } from "./ui";

/**
 * A section per specialist (verdict, confidence, latency, signals), plus the
 * orchestrator's quality notes: disagreements it resolved and anything the
 * specialists missed. Replaces the v1 multi-round transcript: v2 has one
 * round, and the orchestrator weighs it.
 */
export function SpecialistSummary({
  findings,
  verdict,
}: {
  findings: Finding[];
  verdict: Verdict;
}) {
  return (
    <div className="space-y-4">
      {SPECIALISTS.map((name) => (
        <SpecialistSection
          key={name}
          name={name}
          finding={findings.find((f) => f.agent === name)}
        />
      ))}
      {(verdict.disagreements.length > 0 ||
        verdict.missed_by_specialists.length > 0) && (
        <Card>
          <CardBody className="grid gap-4 md:grid-cols-2">
            <NoteList
              title="Disagreements resolved"
              items={verdict.disagreements}
            />
            <NoteList
              title="Missed by the specialists"
              items={verdict.missed_by_specialists}
            />
          </CardBody>
        </Card>
      )}
    </div>
  );
}

/** One specialist: verdict, confidence, latency and every signal it reported. */
function SpecialistSection({
  name,
  finding,
}: {
  name: SpecialistName;
  finding?: Finding;
}) {
  const headingId = useId();
  const visual = SPECIALIST_VISUAL[name];
  const Icon = visual.icon;
  return (
    <section aria-labelledby={headingId}>
      <Card>
        <CardBody className="space-y-4">
          {/* Identity and status are two groups so a narrow screen wraps the
              status row under the name instead of squeezing the name. */}
          <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
            <div className="flex min-w-56 flex-1 items-center gap-3">
              <span
                className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg"
                style={{ background: visual.soft, color: visual.color }}
              >
                <Icon className="h-4 w-4" aria-hidden />
              </span>
              <div className="min-w-0">
                <h4 id={headingId} className="text-base font-semibold text-fg">
                  {visual.label}
                </h4>
                <p className="text-xs text-muted">{visual.role}</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
            {!finding && <p className="text-xs text-muted">No report</p>}
            {finding?.status === "blocked_by_guardrail" && (
              <Badge tone="warn">
                <ShieldOff className="h-3.5 w-3.5" aria-hidden />
                Blocked by guardrail
              </Badge>
            )}
            {finding?.status === "error" && (
              <Badge tone="danger">
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
                Specialist error
              </Badge>
            )}
            {finding?.status === "ok" && (
              <>
                <VerdictBadge verdict={finding.verdict} />
                <span className="text-xs tabular-nums text-fg-subtle">
                  {finding.confidence}% confident
                </span>
              </>
            )}
            {finding && (
              <span className="inline-flex items-center gap-1 text-xs tabular-nums text-fg-subtle">
                <Clock className="h-3.5 w-3.5" aria-hidden />
                <span className="sr-only">Latency </span>
                <span>{formatMs(finding.latency_ms)}</span>
              </span>
            )}
            </div>
          </div>
          {finding?.capture_note && (
            <p className="rounded-lg border border-border bg-surface-2/60 px-3 py-2 text-xs leading-relaxed text-fg-subtle">
              <span className="font-semibold text-fg">Capture: </span>
              {finding.capture_note}
            </p>
          )}
          <SignalList finding={finding} />
        </CardBody>
      </Card>
    </section>
  );
}

function NoteList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <p className="text-sm font-semibold text-fg">
        {title}
      </p>
      {items.length === 0 ? (
        <p className="mt-1 text-sm text-muted">None</p>
      ) : (
        <ul className="mt-1 list-disc space-y-1 pl-4 text-sm text-fg-subtle">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
