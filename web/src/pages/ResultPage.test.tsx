// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const getScan = vi.fn();
const retryScan = vi.fn();
vi.mock("@/lib/api", () => ({
  api: {
    getScan: (...a: unknown[]) => getScan(...a),
    retryScan: (...a: unknown[]) => retryScan(...a),
  },
}));

import { ThemeProvider } from "@/hooks/useTheme";
import { ResultPage } from "./ResultPage";
import { REPORT_POLL_MS } from "@/hooks/useScan";

const failed = {
  scan_id: "s-1",
  url: "https://a.example",
  batch_id: null,
  status: "FAILED",
  queued_at: "2026-09-29T12:00:00Z",
  started_at: null,
  completed_at: "2026-09-29T12:05:00Z",
  queue_wait_ms: null,
  total_ms: null,
  verdict: null,
  findings: [],
  calls: [],
  cost_usd: "0",
  error: "Harness invocation failed (failed after 3 attempts). Correlation id c-9.",
  attempts: 3,
  guardrail_events: ["input_guardrail_intervened"],
  artifacts: { screenshot: null },
};

function renderPage() {
  render(
    <MemoryRouter initialEntries={["/results/s-1"]}>
      <Routes>
        <Route path="/results/:scanId" element={<ResultPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ResultPage", () => {
  it("shows why a scan failed and retries it", async () => {
    getScan
      .mockResolvedValueOnce(failed)
      .mockResolvedValue({ ...failed, status: "PENDING", error: null });
    retryScan.mockResolvedValue({ scan_id: "s-1", status: "PENDING" });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/failed after 3 attempts/)).toBeTruthy(),
    );
    expect(screen.getByText(/It was still scanned/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry scan" }));
    await waitFor(() => expect(retryScan).toHaveBeenCalledWith("s-1"));
    await waitFor(() =>
      expect(getScan.mock.calls.length).toBeGreaterThanOrEqual(2),
    );
  });

  it("never shows an empty failure reason", async () => {
    getScan.mockResolvedValue({ ...failed, error: null });
    renderPage();
    await waitFor(() =>
      expect(
        screen.getByText("The scan failed without a reason; retry it."),
      ).toBeTruthy(),
    );
  });

  describe("verdict-first", () => {
    const complete = {
      ...failed,
      status: "COMPLETE",
      error: null,
      guardrail_events: [],
      total_ms: 30_000,
      verdict: {
        verdict: "phishing",
        risk_score: 95,
        confidence: "high",
        action: "block",
        summary: "Credential form posts off-domain.",
        disagreements: [],
        missed_by_specialists: [],
        report_markdown: "",
      },
    };
    const withReport = {
      ...complete,
      report_status: "READY",
      verdict: { ...complete.verdict, report_markdown: "## Reasoning\nThe judge weighed it." },
    };

    beforeEach(() => {
      vi.useFakeTimers();
      getScan.mockReset();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    function renderThemed() {
      render(
        <ThemeProvider>
          <MemoryRouter initialEntries={["/results/s-1"]}>
            <Routes>
              <Route path="/results/:scanId" element={<ResultPage />} />
            </Routes>
          </MemoryRouter>
        </ThemeProvider>,
      );
    }

    it("shows the verdict at once, then swaps in the report without a refresh", async () => {
      getScan
        .mockResolvedValueOnce({ ...complete, report_status: "PENDING" })
        .mockResolvedValue(withReport);
      renderThemed();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(screen.getByText("PHISHING")).toBeTruthy();
      expect(screen.getByText("Writing the full report")).toBeTruthy();
      expect(screen.queryByText("The judge weighed it.")).toBeNull();

      await act(async () => {
        await vi.advanceTimersByTimeAsync(REPORT_POLL_MS + 100);
      });
      expect(screen.getByText("The judge weighed it.")).toBeTruthy();
      expect(screen.queryByText("Writing the full report")).toBeNull();
      expect(screen.getByText("PHISHING")).toBeTruthy();

      const calls = getScan.mock.calls.length;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(getScan).toHaveBeenCalledTimes(calls);
    });

    it("shows the failed-report message and stops polling", async () => {
      getScan
        .mockResolvedValueOnce({ ...complete, report_status: "PENDING" })
        .mockResolvedValue({ ...complete, report_status: "FAILED", report_error: "Model throttled" });
      renderThemed();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(REPORT_POLL_MS + 100);
      });
      expect(screen.getByText(/The full report could not be generated/)).toBeTruthy();
      expect(screen.getByText("PHISHING")).toBeTruthy();
      const calls = getScan.mock.calls.length;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(getScan).toHaveBeenCalledTimes(calls);
    });

    it("renders a legacy record (no report_status) with its report and polls once", async () => {
      getScan.mockResolvedValue({
        ...complete,
        verdict: { ...complete.verdict, report_markdown: "## Reasoning\nOld report." },
      });
      renderThemed();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(30_000);
      });
      expect(screen.getByText("Old report.")).toBeTruthy();
      expect(screen.queryByRole("status")).toBeNull();
      expect(getScan).toHaveBeenCalledTimes(1);
    });
  });
});
