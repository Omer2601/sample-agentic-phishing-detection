// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/hooks/useTheme";

const getStats = vi.fn();
vi.mock("@/lib/api", () => ({
  api: {
    getStats: (...a: unknown[]) => getStats(...a),
    statsExportUrl: (r: string) => `/api/stats/export?range=${r}`,
  },
}));
vi.mock("@/hooks/useActiveBatches", () => ({
  useActiveBatches: () => ({
    batches: [],
    active: [],
    loaded: true,
    error: null,
    refresh: vi.fn(),
  }),
}));

import { InsightsPage } from "./InsightsPage";

const stats = {
  range: "7d",
  totals: {
    scanned: 50,
    phishing: 38,
    suspicious: 6,
    legitimate: 3,
    unknown: 1,
    error_404: 4,
    site_down: 5,
    failed: 2,
    cost_usd: "7.48",
    input_tokens: 1_200_000,
    output_tokens: 90_000,
    avg_ms: 34_000,
    p95_ms: 52_000,
  },
  daily: [],
  latency_histogram: [],
  by_model: [],
  agentcore: [
    {
      kind: "browser",
      name: "brand_visual",
      count: 49,
      avg_ms: 9000,
      p95_ms: 14000,
      errors: 1,
      blocked: 0,
    },
  ],
  recent_batches: [],
};

function renderPage() {
  render(
    <ThemeProvider>
      <MemoryRouter>
        <InsightsPage />
      </MemoryRouter>
    </ThemeProvider>,
  );
}

describe("InsightsPage", () => {
  it("shows the headline tiles for the range", async () => {
    getStats.mockResolvedValue(stats);
    renderPage();
    await waitFor(() => expect(screen.getByText("URLs scanned")).toBeTruthy());
    expect(screen.getByText("50")).toBeTruthy();
    expect(screen.getByText("$7.48")).toBeTruthy();
    expect(screen.getByText("52s")).toBeTruthy();
    expect(getStats).toHaveBeenCalledWith("7d");
  });

  it("says a model's cost is unknown, never $0, when it has no price", async () => {
    getStats.mockResolvedValue({
      ...stats,
      totals: { ...stats.totals, unpriced_scans: 2 },
      by_model: [
        {
          model_id: "xx.anthropic.claude-future-9",
          input_tokens: 500,
          output_tokens: 50,
          cost_usd: "0.0000",
          cost_known: false,
        },
      ],
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Cost unknown")).toBeTruthy());
    expect(screen.queryByText("$0.0000")).toBeNull();
    expect(
      screen.getByText("At least: 2 scans used a model with no price"),
    ).toBeTruthy();
  });

  it("names Error 404 scans in the failed or unknown tile hint", async () => {
    getStats.mockResolvedValue(stats);
    renderPage();
    await waitFor(() => expect(screen.getByText("URLs scanned")).toBeTruthy());
    expect(screen.getByText("2 failed, 1 unknown, 4 Error 404, 5 Site down")).toBeTruthy();
    // A 404 is not a failure, so it stays out of the tile's value (2 + 1).
    const tile = screen.getByText("Failed or unknown").closest(".card") as HTMLElement;
    expect(tile.querySelector("p")?.textContent).toBe("3");
  });

  it("treats a missing error_404 count (older data) as zero", async () => {
    const { error_404: _omit, site_down: _omit2, ...legacyTotals } = stats.totals;
    getStats.mockResolvedValue({ ...stats, totals: legacyTotals });
    renderPage();
    await waitFor(() => expect(screen.getByText("URLs scanned")).toBeTruthy());
    expect(screen.getByText("2 failed, 1 unknown, 0 Error 404, 0 Site down")).toBeTruthy();
  });

  it("reloads when the range changes and exports the same range", async () => {
    getStats.mockResolvedValue(stats);
    renderPage();
    await waitFor(() => expect(getStats).toHaveBeenCalledWith("7d"));
    fireEvent.click(screen.getByRole("radio", { name: "30 days" }));
    await waitFor(() => expect(getStats).toHaveBeenCalledWith("30d"));
    expect(
      screen.getByRole("link", { name: /Export CSV/ }).getAttribute("href"),
    ).toBe("/api/stats/export?range=30d");
  });

  it("lists AgentCore call stats", async () => {
    getStats.mockResolvedValue(stats);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("Browser session")).toBeTruthy(),
    );
    expect(screen.getByText("brand_visual")).toBeTruthy();
  });

  it("ignores a slower response for a range that is no longer selected", async () => {
    getStats.mockReset();
    // The 7d request resolves only after the 30d one, and must not overwrite it.
    let resolve7d: (v: unknown) => void = () => {};
    getStats.mockImplementation((r: string) =>
      r === "7d"
        ? new Promise((res) => {
            resolve7d = res;
          })
        : Promise.resolve({
            ...stats,
            range: "30d",
            totals: { ...stats.totals, scanned: 300 },
          }),
    );
    renderPage();
    await waitFor(() => expect(getStats).toHaveBeenCalledWith("7d"));
    fireEvent.click(screen.getByRole("radio", { name: "30 days" }));
    await waitFor(() => expect(screen.getByText("300")).toBeTruthy());
    resolve7d(stats);
    // Let the stale promise settle, then confirm the 30d numbers are still shown.
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.getByText("300")).toBeTruthy();
    expect(screen.queryByText("50")).toBeNull();
  });

  it("shows over 2m for totals and AgentCore calls flagged p95_over_max", async () => {
    getStats.mockReset();
    getStats.mockResolvedValue({
      ...stats,
      totals: { ...stats.totals, p95_ms: 120_000, p95_over_max: true },
      agentcore: [{ ...stats.agentcore[0], p95_ms: 120_000, p95_over_max: true }],
    });
    renderPage();
    await waitFor(() => expect(screen.getAllByText("over 2m")).toHaveLength(2));
  });
});
