// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ThemeProvider } from "@/hooks/useTheme";

const getBatch = vi.fn();
const retryFailed = vi.fn();
const getBatchReport = vi.fn();
const startDownload = vi.fn();
vi.mock("@/lib/download", () => ({
  startDownload: (...a: unknown[]) => startDownload(...a),
}));
const refresh = vi.fn(async () => {});
vi.mock("@/lib/api", () => ({
  api: {
    getBatch: (...a: unknown[]) => getBatch(...a),
    retryFailed: (...a: unknown[]) => retryFailed(...a),
    getBatchReport: (...a: unknown[]) => getBatchReport(...a),
  },
}));
vi.mock("@/hooks/useActiveBatches", () => ({
  // Short, so the polling tests below run in real time.
  BATCH_POLL_MS: 20,
  useActiveBatches: () => ({
    batches: [],
    active: [],
    loaded: true,
    error: null,
    refresh,
  }),
}));

import { BatchDetailPage } from "./BatchDetailPage";

const scan = (id: string, status: string, error: string | null) => ({
  scan_id: id,
  url: `https://${id}.example`,
  batch_id: "b-1",
  status,
  queued_at: "2026-09-29T12:00:00Z",
  started_at: null,
  completed_at: "2026-09-29T12:01:00Z",
  queue_wait_ms: null,
  total_ms: 30_000,
  verdict: null,
  findings: [],
  calls: [],
  cost_usd: "0.10",
  error,
  attempts: 3,
  guardrail_events: [],
});

// Shape of GET /batches/{id} as backend/phish_backend/api/routes/batches.py
// builds it: the BatchRecord under "batch", and the detail-only fields
// (invalid_rows as a list of skipped rows, error, p50/p95) beside it.
const invalidRow = (row: number) => ({ row, value: "nope", reason: "not a URL" });

const detail = {
  batch: {
    batch_id: "b-1",
    source: "ui",
    total: 3,
    status_counts: { COMPLETE: 1, FAILED: 2 },
    verdict_counts: { phishing: 1 },
    created_at: "2026-09-29T12:00:00Z",
    first_started_at: "2026-09-29T12:00:05Z",
    completed_at: "2026-09-29T12:02:00Z",
    wall_clock_ms: 120_000,
    sum_scan_ms: 90_000,
    cost_usd: "0.30",
    awaiting_upload: false,
    split_at: "2026-09-29T12:00:01Z",
    error: null,
  },
  invalid_rows: [2, 3, 5, 8].map(invalidRow),
  error: null,
  p50_ms: 31_000,
  p95_ms: 47_000,
  p95_over_max: false,
  items: [
    scan("ok", "COMPLETE", null),
    scan("bad", "FAILED", "Model throttled (failed after 3 attempts)."),
    scan("gone", "FAILED", null),
  ],
  next: null,
};

function renderPage() {
  render(
    <ThemeProvider>
      <MemoryRouter initialEntries={["/batch/b-1"]}>
        <Routes>
          <Route path="/batch/:batchId" element={<BatchDetailPage />} />
        </Routes>
      </MemoryRouter>
    </ThemeProvider>,
  );
}

describe("BatchDetailPage", () => {
  it("shows a disclaimer badge in the Verdict header and no page-level banner (AppShell owns it)", async () => {
    getBatch.mockResolvedValue(detail);
    renderPage();
    await waitFor(() => expect(screen.getByTestId("disclaimer-badge")).toBeTruthy());
    expect(screen.getByTestId("disclaimer-badge").textContent).toContain(
      "AI OUTPUT: HUMAN REVIEW REQUIRED",
    );
    expect(screen.queryByTestId("disclaimer-banner")).toBeNull();
  });

  it("shows Error 404 for a 404 row and counts it in the mix", async () => {
    const notFound = {
      ...scan("nf", "COMPLETE", null),
      verdict: {
        verdict: "error_404",
        risk_score: 0,
        confidence: "high",
        action: "allow",
        summary: "s",
        disagreements: [],
        missed_by_specialists: [],
        report_markdown: "r",
      },
    };
    getBatch.mockResolvedValue({
      ...detail,
      batch: { ...detail.batch, verdict_counts: { phishing: 1, error_404: 1 } },
      items: [notFound],
    });
    renderPage();
    await waitFor(() => expect(screen.getAllByText("Error 404").length).toBeGreaterThan(0));
    expect(screen.queryByText("Unknown")).toBeNull();
    expect(screen.getByText(/1 error 404/)).toBeTruthy();
  });

  it("shows p50 and p95 scan time and skipped rows from the server", async () => {
    getBatch.mockResolvedValue(detail);
    renderPage();
    await waitFor(() => expect(screen.getByText("31s")).toBeTruthy());
    expect(screen.getByText("47s")).toBeTruthy();
    expect(screen.getByText(/4 invalid rows/)).toBeTruthy();
  });

  it("lists each failure reason and retries the failed scans", async () => {
    getBatch.mockResolvedValue(detail);
    retryFailed.mockResolvedValue({ batch_id: "b-1", retried: 2 });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/Model throttled/)).toBeTruthy(),
    );
    expect(screen.getByText(/No reason recorded/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry 2 failed" }));
    await waitFor(() => expect(retryFailed).toHaveBeenCalledWith("b-1"));
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(getBatch.mock.calls.length).toBeGreaterThan(1);
  });

  const running = {
    ...detail,
    batch: {
      ...detail.batch,
      completed_at: null,
      wall_clock_ms: null,
      status_counts: { COMPLETE: 1, RUNNING: 2 },
    },
    items: [scan("ok", "COMPLETE", null)],
  };

  it("keeps the last good detail and keeps polling when a poll fails", async () => {
    // The poll after the failure is held until the error state has been checked, so a
    // fast next poll cannot clear the error first (it did on a loaded machine).
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    getBatch.mockReset();
    getBatch
      .mockResolvedValueOnce(running)
      .mockRejectedValueOnce(new Error("Gateway timeout"))
      .mockImplementationOnce(() => held.then(() => running))
      .mockResolvedValue(running);
    renderPage();
    await waitFor(() => expect(screen.getByText(/Gateway timeout/)).toBeTruthy());
    // The last good detail is still on screen under the error.
    expect(screen.getByText("31s")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Retry now" })).toBeTruthy();
    release();
    // Polling continued on its own and the next success cleared the error.
    await waitFor(() => expect(screen.queryByText(/Gateway timeout/)).toBeNull());
    expect(getBatch.mock.calls.length).toBeGreaterThanOrEqual(3);
  });

  it("retries on demand after a failed first load", async () => {
    getBatch.mockReset();
    getBatch.mockRejectedValue(new Error("Network down"));
    renderPage();
    await waitFor(() => expect(screen.getByText(/Network down/)).toBeTruthy());
    getBatch.mockResolvedValue(detail);
    fireEvent.click(screen.getByRole("button", { name: "Retry now" }));
    await waitFor(() => expect(screen.getByText("31s")).toBeTruthy());
    expect(screen.queryByText(/Network down/)).toBeNull();
  });

  it("shows over 2m when the batch p95 exceeds the top latency bucket", async () => {
    getBatch.mockReset();
    getBatch.mockResolvedValue({
      ...detail,
      p95_ms: 120_000,
      p95_over_max: true,
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("over 2m")).toBeTruthy());
  });

  it("presents bucket-edge batch percentiles as bounds, not measurements", async () => {
    getBatch.mockReset();
    getBatch.mockResolvedValue({
      ...detail,
      p50_ms: 60_000,
      p95_ms: 90_000,
      p50_bound: true,
      p95_bound: true,
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("up to 1m 00s")).toBeTruthy());
    expect(screen.getByText("up to 1m 30s")).toBeTruthy();
  });

  it("shows the upload error the API returns beside the batch", async () => {
    getBatch.mockReset();
    getBatch.mockResolvedValue({ ...detail, error: "CSV was never uploaded" });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("CSV was never uploaded")).toBeTruthy(),
    );
  });

  it("downloads the batch HTML report", async () => {
    getBatch.mockReset();
    getBatch.mockResolvedValue(detail);
    getBatchReport.mockResolvedValue({ url: "https://s3.example/b", expires_in: 900 });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Download report" }));
    await waitFor(() => expect(startDownload).toHaveBeenCalledWith("https://s3.example/b"));
    expect(getBatchReport).toHaveBeenCalledWith("b-1");
  });

  it("shows the verdict and a report-pending hint on a COMPLETE row, not on READY or legacy rows", async () => {
    const withVerdict = (id: string, extra: Record<string, unknown>) => ({
      ...scan(id, "COMPLETE", null),
      verdict: { verdict: "phishing", risk_score: 90 },
      ...extra,
    });
    getBatch.mockResolvedValue({
      ...detail,
      items: [
        withVerdict("slow", { report_status: "PENDING" }),
        withVerdict("fast", { report_status: "READY" }),
        withVerdict("old", {}),
      ],
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("https://slow.example")).toBeTruthy());
    // Verdict is there for all three rows.
    expect(screen.getAllByText("Phishing").length).toBeGreaterThanOrEqual(3);
    // Hint appears for the PENDING row only (desktop and mobile slots both render).
    const rows = screen.getAllByRole("row");
    const rowOf = (needle: string) => rows.find((r) => r.textContent?.includes(needle))!;
    expect(rowOf("slow.example").textContent).toContain("Report pending");
    expect(rowOf("fast.example").textContent).not.toContain("Report pending");
    expect(rowOf("old.example").textContent).not.toContain("Report pending");
  });

  it("keeps polling a finished batch while a report is pending, then clears the hint and stops", async () => {
    const withVerdict = (id: string, report_status: string) => ({
      ...scan(id, "COMPLETE", null),
      verdict: { verdict: "legitimate", risk_score: 3 },
      report_status,
    });
    const finished = (status: string) => ({
      ...detail,
      items: [withVerdict("slow", status), withVerdict("fast", "READY")],
    });
    getBatch.mockReset();
    // The batch is already complete (completed_at is set in `detail`) but a report is pending.
    getBatch
      .mockResolvedValueOnce(finished("PENDING"))
      .mockResolvedValue(finished("READY"));
    renderPage();
    const rowOf = (needle: string) =>
      screen.getAllByRole("row").find((r) => r.textContent?.includes(needle))!;
    await waitFor(() =>
      expect(rowOf("slow.example").textContent).toContain("Report pending"),
    );
    // Without the fix the page never asked again and the hint stayed until a reload.
    await waitFor(() =>
      expect(rowOf("slow.example").textContent).not.toContain("Report pending"),
    );
    expect(getBatch.mock.calls.length).toBeGreaterThanOrEqual(2);
    // Nothing is pending any more, so polling stops.
    const calls = getBatch.mock.calls.length;
    await new Promise((resolve) => setTimeout(resolve, 2500));
    expect(getBatch.mock.calls.length).toBe(calls);
  });
});
