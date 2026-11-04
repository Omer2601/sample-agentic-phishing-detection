// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Ban, CircleCheck, TriangleAlert } from "lucide-react";
import type { Action, ConfidenceBand, Verdict } from "@/lib/types";
import {
  ACTION_STYLE,
  CONFIDENCE_STYLE,
  VERDICT_STYLE,
} from "@/lib/verdictStyle";
import { cn } from "@/lib/utils";
import { VerdictGauge } from "./VerdictGauge";
import { VerdictIcon } from "./VerdictBadge";
import { Badge } from "./ui";
import { DisclaimerBadge } from "./DisclaimerBanner";

const TONE_CLASSES = {
  danger: {
    ring: "ring-danger/40 from-danger/10",
    chip: "bg-danger/15 text-danger",
    text: "text-danger",
  },
  warn: {
    ring: "ring-warn/40 from-warn/10",
    chip: "bg-warn/15 text-warn",
    text: "text-warn",
  },
  safe: {
    ring: "ring-safe/40 from-safe/10",
    chip: "bg-safe/15 text-safe",
    text: "text-safe",
  },
  neutral: {
    ring: "ring-border from-surface-2/40",
    chip: "bg-surface-2 text-fg-subtle",
    text: "text-fg",
  },
} as const;

export function ConfidenceMeter({
  confidence,
}: {
  confidence: ConfidenceBand;
}) {
  const meta = CONFIDENCE_STYLE[confidence];
  return (
    <span className="inline-flex items-center gap-1.5" aria-label={meta.label}>
      <span className="flex items-end gap-0.5" aria-hidden="true">
        {[1, 2, 3].map((n) => (
          <span
            key={n}
            className={cn(
              "w-1.5 rounded-xs transition-colors",
              n <= meta.dots ? "bg-accent" : "bg-fg/15",
            )}
            style={{ height: `${6 + n * 4}px` }}
          />
        ))}
      </span>
      <span className="text-xs font-medium text-fg-subtle">{meta.label}</span>
    </span>
  );
}

export function RecommendationPill({ action }: { action: Action }) {
  const style = ACTION_STYLE[action];
  const icon =
    action === "block" ? (
      <Ban className="h-3.5 w-3.5" aria-hidden />
    ) : action === "warn" ? (
      <TriangleAlert className="h-3.5 w-3.5" aria-hidden />
    ) : (
      <CircleCheck className="h-3.5 w-3.5" aria-hidden />
    );
  return (
    <Badge tone={style.token}>
      {icon}
      {style.label}
    </Badge>
  );
}

/** Leads the result: the orchestrator's verdict, gauge, summary, confidence and action. */
export function VerdictHero({
  url,
  verdict,
}: {
  url: string;
  verdict: Verdict;
}) {
  const style = VERDICT_STYLE[verdict.verdict];
  const tone = TONE_CLASSES[style.token];
  return (
    <div className={cn("card overflow-hidden ring-1", tone.ring)}>
      <div
        className={cn(
          "grid gap-6 bg-linear-to-br/srgb to-transparent p-5 sm:p-6 md:grid-cols-[1fr_auto] md:items-center",
          tone.ring,
        )}
      >
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "inline-flex h-11 w-11 items-center justify-center rounded-xl",
                tone.chip,
              )}
            >
              <VerdictIcon verdict={verdict.verdict} className="h-6 w-6" />
            </span>
            <div className="min-w-0">
              <h2
                className={cn(
                  "text-2xl font-extrabold leading-none tracking-tight",
                  tone.text,
                )}
              >
                {style.label.toUpperCase()}
              </h2>
              <p
                className="mt-1 truncate font-mono text-xs text-muted"
                title={url}
              >
                {url}
              </p>
            </div>
          </div>
          <p className="mt-4 max-w-prose text-sm leading-relaxed text-fg sm:text-[15px]">
            {verdict.summary}
          </p>
          <div className="mt-5 flex flex-wrap items-center gap-4">
            <ConfidenceMeter confidence={verdict.confidence} />
            <span className="h-4 w-px bg-border" aria-hidden="true" />
            {/* Label and pill wrap together, never apart. */}
            <span className="inline-flex items-center gap-2">
              <span className="text-xs text-fg-subtle">Recommended action</span>
              <RecommendationPill action={verdict.action} />
            </span>
          </div>
          <DisclaimerBadge className="mt-3" />
        </div>
        <div className="mx-auto md:mx-0">
          <VerdictGauge score={verdict.risk_score} />
        </div>
      </div>
    </div>
  );
}
