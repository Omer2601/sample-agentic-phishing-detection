// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Check, Loader2, X } from "lucide-react";
import type { ScanProgress } from "@/lib/types";
import { cn } from "@/lib/utils";
import { STAGE_SEQUENCE, stageIndex } from "@/lib/scanProgress";
import { Card, CardBody, Progress } from "./ui";

/**
 * Compact staged progress for a scan of about 30 to 40 seconds. During a run the user does not
 * benefit from reading all eight stage descriptions at once, so we surface only
 * the stage that is currently running (or that failed) in full, and compress the
 * rest into a "Step N of M" counter with one dot per stage. This preserves the
 * useful signal (URL, percentage, live bar) while cutting the reading load, and
 * still gives screen readers a per-stage status via the dot list.
 */
export function StagedProgress({
  url,
  progress,
  onCancel,
}: {
  url: string;
  progress: ScanProgress | null;
  onCancel?: () => void;
}) {
  // Stages shown to the user (drop the terminal DONE row).
  const stages = STAGE_SEQUENCE.filter((s) => s.stage !== "DONE");
  const rawIndex = progress ? stageIndex(progress.stage) : 0;
  // Clamp into the visible range so a DONE (or unknown) snapshot cannot overflow
  // and always leaves a real stage to describe, never a contextless spinner.
  const current = Math.min(Math.max(rawIndex, 0), stages.length - 1);
  const overall = progress?.progress ?? 0;
  const failed = progress?.status === "FAILED";
  const active = stages[current];

  return (
    <Card>
      <CardBody>
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-semibold text-fg">Analysing in real time</p>
            <p className="mt-0.5 truncate font-mono text-xs text-muted" title={url}>
              {url}
            </p>
          </div>
          <div className="shrink-0 text-right">
            <p className="tabular-nums text-lg font-bold text-fg">
              {Math.round(overall * 100)}%
            </p>
            <p className="text-[11px] text-muted">
              {failed ? "failed" : overall >= 0.95 ? "finishing up" : "in progress"}
            </p>
          </div>
        </div>

        <div className="mt-4">
          <Progress value={overall} tone={failed ? "danger" : "accent"} />
          {/* The bar is capped below 100% while a job is pending, so it can never
              claim a completion the API has not confirmed. */}
        </div>

        {/* The current stage, shown in full: the one thing worth reading now. */}
        <div
          className={cn(
            "mt-4 flex items-center gap-3 rounded-lg px-3 py-2.5",
            failed ? "bg-danger/5" : "bg-accent/5",
          )}
          aria-live="polite"
        >
          <span
            className={cn(
              "flex h-8 w-8 shrink-0 items-center justify-center rounded-full border",
              failed
                ? "border-danger/40 bg-danger/15 text-danger"
                : "border-accent bg-accent/15 text-accent",
            )}
          >
            {failed ? <X className="h-4 w-4" /> : <Loader2 className="h-4 w-4 animate-spin" />}
          </span>
          <div className="min-w-0">
            <p className="text-sm font-medium text-fg">
              {failed ? `Failed at ${active.label}` : active.label}
            </p>
            <p className="text-xs text-fg-subtle">{active.description}</p>
          </div>
        </div>

        {/* Overall position: a counter plus one dot per stage, no per-stage prose. */}
        <div className="mt-3">
          <p className="text-[11px] font-medium text-muted">
            Step {current + 1} of {stages.length}
          </p>
          <ol className="mt-1.5 flex items-center gap-1.5" aria-label="Scan stages">
            {stages.map((s, i) => {
              const state =
                failed && i === current
                  ? "failed"
                  : i < current
                    ? "done"
                    : i === current
                      ? "active"
                      : "todo";
              const status =
                state === "done"
                  ? "complete"
                  : state === "failed"
                    ? "failed"
                    : state === "active"
                      ? "in progress"
                      : "pending";
              return (
                <li
                  key={s.stage}
                  aria-current={state === "active" ? "step" : undefined}
                  aria-label={`${s.label}: ${status}`}
                  className={cn(
                    "flex h-4 w-4 items-center justify-center rounded-full border text-safe",
                    state === "done" && "border-safe/40 bg-safe/15",
                    state === "active" && "border-accent bg-accent animate-pulse-ring",
                    state === "failed" && "border-danger/40 bg-danger",
                    state === "todo" && "border-border bg-surface-2",
                  )}
                >
                  {state === "done" ? <Check className="h-2.5 w-2.5" /> : null}
                </li>
              );
            })}
          </ol>
        </div>

        {onCancel && !failed && (
          <div className="mt-4 flex justify-end">
            <button
              onClick={onCancel}
              className="text-xs font-medium text-muted underline-offset-4 hover:text-fg hover:underline"
            >
              Cancel scan
            </button>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
