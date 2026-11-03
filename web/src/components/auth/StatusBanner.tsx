// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { cn } from "@/lib/utils";

/**
 * The single announcement region for an auth form's submit result.
 *
 * It is ALWAYS rendered, even with nothing to say, because a live region that is
 * inserted into the DOM at the same moment as its text is announced
 * inconsistently across screen readers. Keeping the element mounted and changing
 * only its contents is what makes the announcement reliable.
 *
 * role="status" is polite by design: a submit result is not an interruption. It
 * is also the ONLY thing that announces a failed submit, which is why the
 * per-field error text carries no alert role of its own; two announcements for
 * one event is worse than one.
 */

export type StatusTone = "info" | "error" | "success";

export interface StatusMessage {
  tone: StatusTone;
  text: string;
}

const toneClass: Record<StatusTone, string> = {
  info: "border-border bg-surface-2/60 text-fg-subtle",
  error: "border-danger/30 bg-danger/10 text-danger",
  success: "border-safe/30 bg-safe/10 text-safe",
};

export function StatusBanner({ status }: { status: StatusMessage | null }) {
  return (
    <div role="status" aria-live="polite">
      {status ? (
        <p
          className={cn(
            "mb-5 rounded-xl border px-3.5 py-2.5 text-xs font-medium",
            toneClass[status.tone],
          )}
        >
          {status.text}
        </p>
      ) : null}
    </div>
  );
}
