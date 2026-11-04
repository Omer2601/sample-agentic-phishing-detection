// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { TriangleAlert } from "lucide-react";
import {
  DISCLAIMER_BADGE_TEXT,
  DISCLAIMER_TEXT,
  DISCLAIMER_TITLE,
} from "@/lib/disclaimer";
import { cn } from "@/lib/utils";

/**
 * Bold, bordered notice that model output needs a human reviewer. It uses the
 * warn token with foreground text (not warn-coloured text) so contrast holds in
 * both themes, and role="note" so assistive tech announces it as supplementary
 * content without interrupting.
 */
export function DisclaimerBanner({ className }: { className?: string }) {
  return (
    <div
      role="note"
      data-testid="disclaimer-banner"
      className={cn(
        "flex items-start gap-3 rounded-xl border-2 border-warn bg-warn/15 px-4 py-3 text-fg",
        className,
      )}
    >
      <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-warn" aria-hidden />
      <div className="min-w-0">
        <p className="text-sm font-extrabold leading-snug">{DISCLAIMER_TITLE}</p>
        <p className="mt-0.5 text-sm font-bold leading-snug">{DISCLAIMER_TEXT}</p>
      </div>
    </div>
  );
}

/** Compact bold form of the same warning, for places a full banner would not fit. */
export function DisclaimerBadge({ className }: { className?: string }) {
  return (
    <span
      role="note"
      data-testid="disclaimer-badge"
      title={`${DISCLAIMER_TITLE}. ${DISCLAIMER_TEXT}`}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border-2 border-warn bg-warn/15 px-2 py-0.5 text-[11px] font-extrabold uppercase tracking-wide text-fg",
        className,
      )}
    >
      <TriangleAlert className="h-3.5 w-3.5 shrink-0 text-warn" aria-hidden />
      {DISCLAIMER_BADGE_TEXT}
    </span>
  );
}
