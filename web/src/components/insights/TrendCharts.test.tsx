// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { ThemeProvider } from "@/hooks/useTheme";
import type { DailyStats } from "@/lib/types";
import { CostTrendChart } from "./CostTrendChart";
import { LatencyChart } from "./LatencyChart";
import { VerdictTrendChart } from "./VerdictTrendChart";

// The live defect: one 35 s phishing scan at 22:42 PDT on Sep 30, which the
// server buckets as Oct 1 UTC.
const NOW = new Date("2026-10-01T05:42:00Z");
const today: DailyStats = {
  day: "2026-10-01",
  phishing: 1,
  suspicious: 0,
  legitimate: 0,
  unknown: 0,
  error_404: 0,
  failed: 0,
  cost_usd: "0.1361",
  input_tokens: 29_100,
  output_tokens: 3_000,
};

function tableRows(): string[] {
  fireEvent.click(screen.getByRole("button", { name: "Table" }));
  const table = screen.getByRole("table");
  return within(table)
    .getAllByRole("row")
    .slice(1)
    .map((r) => r.textContent ?? "");
}

describe("trend charts", () => {
  it("draws today's verdicts on today, with zero days before it", () => {
    render(
      <ThemeProvider>
        <VerdictTrendChart daily={[today]} range="7d" now={NOW} />
      </ThemeProvider>,
    );
    const rows = tableRows();
    expect(rows).toHaveLength(7);
    expect(rows[0]).toBe("Sep 25000");
    expect(rows.at(-1)).toBe("Oct 1100");
  });

  it("draws today's cost on today", () => {
    render(
      <ThemeProvider>
        <CostTrendChart daily={[today]} range="7d" now={NOW} />
      </ThemeProvider>,
    );
    const rows = tableRows();
    expect(rows.at(-1)).toBe("Oct 1$0.1361");
    expect(rows.slice(0, -1).every((r) => r.endsWith("$0.0000"))).toBe(true);
  });

  it("puts a 35 s scan in the 'up to 40s' bucket", () => {
    render(
      <ThemeProvider>
        <LatencyChart histogram={[{ upper_ms: 40_000, count: 1 }]} />
      </ThemeProvider>,
    );
    const rows = tableRows();
    expect(rows).toContain("up to 40s1");
    expect(rows).toContain("up to 20s0");
  });
});
