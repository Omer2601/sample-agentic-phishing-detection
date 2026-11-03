// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useId, useState, type ReactNode, type KeyboardEvent } from "react";
import { cn } from "@/lib/utils";

export interface TabItem {
  id: string;
  label: ReactNode;
  content: ReactNode;
}

/**
 * A minimal, accessible tab list. Implements the WAI-ARIA tabs pattern:
 * roving arrow-key focus, Home/End, and proper aria wiring.
 *
 * `label` is required because a tablist needs an accessible name that says what
 * the tabs switch between, and that differs per usage.
 */
export function Tabs({
  items,
  label,
  className,
}: {
  items: TabItem[];
  label: string;
  className?: string;
}) {
  const [active, setActive] = useState(0);
  const baseId = useId();

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    const last = items.length - 1;
    let next = active;
    if (e.key === "ArrowRight") next = active === last ? 0 : active + 1;
    else if (e.key === "ArrowLeft") next = active === 0 ? last : active - 1;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = last;
    else return;
    e.preventDefault();
    setActive(next);
    document.getElementById(`${baseId}-tab-${next}`)?.focus();
  };

  return (
    <div className={className}>
      <div
        role="tablist"
        aria-label={label}
        className="flex flex-wrap gap-1 rounded-xl border border-border bg-surface-2/60 p-1"
      >
        {items.map((item, i) => {
          const selected = i === active;
          return (
            <button
              key={item.id}
              id={`${baseId}-tab-${i}`}
              role="tab"
              aria-selected={selected}
              aria-controls={`${baseId}-panel-${i}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => setActive(i)}
              onKeyDown={onKeyDown}
              className={cn(
                "flex-1 whitespace-nowrap rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                selected
                  ? "bg-surface text-fg shadow-xs"
                  : "text-fg-subtle hover:text-fg",
              )}
            >
              {item.label}
            </button>
          );
        })}
      </div>
      {items.map((item, i) => (
        <div
          key={item.id}
          id={`${baseId}-panel-${i}`}
          role="tabpanel"
          aria-labelledby={`${baseId}-tab-${i}`}
          hidden={i !== active}
          className="pt-4 animate-fade-in"
        >
          {i === active && item.content}
        </div>
      ))}
    </div>
  );
}
