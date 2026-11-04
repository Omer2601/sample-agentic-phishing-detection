// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Card, CardBody } from "@/components/ui";

export interface ChartTable {
  columns: string[];
  rows: (string | number)[][];
}

/** Title, legend, and a Chart or Table toggle. Every chart ships a table view. */
export function ChartCard({
  title,
  subtitle,
  legend,
  table,
  children,
}: {
  title: string;
  subtitle?: string;
  legend?: ReactNode;
  table: ChartTable;
  children: ReactNode;
}) {
  const [view, setView] = useState<"chart" | "table">("chart");
  const toggle = (v: "chart" | "table", label: string) => (
    <button
      type="button"
      aria-pressed={view === v}
      onClick={() => setView(v)}
      className={cn(
        "rounded-lg px-2 py-1 text-[11px] font-medium transition-colors",
        view === v ? "bg-surface-2 text-fg" : "text-muted hover:text-fg",
      )}
    >
      {label}
    </button>
  );
  return (
    <Card>
      <CardBody className="space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-fg">{title}</h3>
            {subtitle && <p className="text-[11px] text-muted">{subtitle}</p>}
          </div>
          <div className="flex gap-1">
            {toggle("chart", "Chart")}
            {toggle("table", "Table")}
          </div>
        </div>
        {legend}
        {view === "chart" ? (
          <div className="animate-fade-in">{children}</div>
        ) : (
          <div className="max-h-64 overflow-auto animate-fade-in">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-muted">
                  {table.columns.map((c) => (
                    <th key={c} className="px-2 py-1.5 font-medium">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {table.rows.map((r, i) => (
                  <tr
                    key={i}
                    className="border-b border-border/60 last:border-0"
                  >
                    {r.map((cell, j) => (
                      <td
                        key={j}
                        className="px-2 py-1.5 tabular-nums text-fg-subtle"
                      >
                        {cell}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
