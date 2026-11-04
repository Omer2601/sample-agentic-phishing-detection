// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/hooks/useTheme";

const getHistory = vi.fn();
vi.mock("@/lib/api", () => ({
  api: { getHistory: (...a: unknown[]) => getHistory(...a) },
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

import { HistoryPage } from "./HistoryPage";

const row = (id: string) => ({
  scan_id: id,
  url: `https://${id}.example`,
  status: "COMPLETE",
  queued_at: "2026-09-29T12:00:00Z",
  total_ms: 30_000,
  cost_usd: "0.12",
  batch_id: null,
  verdict: { verdict: "phishing", risk_score: 90 },
});

describe("HistoryPage", () => {
  it("pages through scans with Load more", async () => {
    getHistory
      .mockResolvedValueOnce({ items: [row("one")], next: "t2" })
      .mockResolvedValueOnce({ items: [row("two")], next: null });
    render(
      <ThemeProvider>
        <MemoryRouter>
          <HistoryPage />
        </MemoryRouter>
      </ThemeProvider>,
    );
    await waitFor(() =>
      expect(screen.getByText("https://one.example")).toBeTruthy(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() =>
      expect(screen.getByText("https://two.example")).toBeTruthy(),
    );
    expect(getHistory).toHaveBeenLastCalledWith("t2");
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  });

  it("shows Error 404 for a 404 scan, never Unknown", async () => {
    getHistory.mockResolvedValue({
      items: [{ ...row("gone"), verdict: { verdict: "error_404", risk_score: 0 } }],
      next: null,
    });
    render(
      <ThemeProvider>
        <MemoryRouter>
          <HistoryPage />
        </MemoryRouter>
      </ThemeProvider>,
    );
    await waitFor(() => expect(screen.getByText("Error 404")).toBeTruthy());
    expect(screen.queryByText("Unknown")).toBeNull();
  });

  it("labels its tabs as history views, not evidence", async () => {
    getHistory.mockResolvedValue({ items: [], next: null });
    render(
      <ThemeProvider>
        <MemoryRouter>
          <HistoryPage />
        </MemoryRouter>
      </ThemeProvider>,
    );
    expect(screen.getByRole("tablist", { name: "History views" })).toBeTruthy();
    expect(screen.queryByRole("tablist", { name: "Evidence categories" })).toBeNull();
    await waitFor(() => expect(getHistory).toHaveBeenCalled());
  });

  it("hints that the report is pending next to a verdict that is already in", async () => {
    getHistory.mockResolvedValueOnce({
      items: [
        { ...row("slow"), report_status: "PENDING" },
        { ...row("fast"), report_status: "READY" },
        row("old"),
      ],
      next: null,
    });
    render(
      <ThemeProvider>
        <MemoryRouter>
          <HistoryPage />
        </MemoryRouter>
      </ThemeProvider>,
    );
    await waitFor(() => expect(screen.getByText("https://slow.example")).toBeTruthy());
    expect(screen.getAllByText("Phishing").length).toBe(3);
    expect(screen.getAllByText("Report pending")).toHaveLength(1);
  });
});
