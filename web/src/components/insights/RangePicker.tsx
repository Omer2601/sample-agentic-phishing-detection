// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { RANGES } from "@/lib/insights";
import type { StatsRange } from "@/lib/types";
import { cn } from "@/lib/utils";

export function RangePicker({
  value,
  onChange,
}: {
  value: StatsRange;
  onChange: (r: StatsRange) => void;
}) {
  return (
    <div
      role="radiogroup"
      aria-label="Time range"
      className="inline-flex rounded-xl border border-border bg-surface p-1"
    >
      {RANGES.map((r) => (
        <button
          key={r.id}
          type="button"
          role="radio"
          aria-checked={value === r.id}
          onClick={() => onChange(r.id)}
          className={cn(
            "rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
            value === r.id
              ? "bg-accent/15 text-accent"
              : "text-fg-subtle hover:text-fg",
          )}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}
