// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";

const getScan = vi.fn();
vi.mock("@/lib/api", () => ({
  api: { getScan: (...a: unknown[]) => getScan(...a) },
}));

import {
  REPORT_POLL_CAP_MS,
  REPORT_POLL_MS,
  SCAN_POLL_MS,
  nextReportDelay,
  useScanRecord,
} from "./useScan";

const base = {
  scan_id: "s-1",
  url: "https://a.example",
  findings: [],
  calls: [],
  artifacts: { screenshot: null },
};

beforeEach(() => {
  vi.useFakeTimers();
  getScan.mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("useScanRecord", () => {
  it("polls until the scan is terminal, then stops", async () => {
    getScan
      .mockResolvedValueOnce({ ...base, status: "RUNNING" })
      .mockResolvedValueOnce({ ...base, status: "COMPLETE" });
    const { result } = renderHook(() => useScanRecord("s-1"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(SCAN_POLL_MS * 4);
    });
    expect(result.current.record?.status).toBe("COMPLETE");
    expect(getScan).toHaveBeenCalledTimes(2);
  });

  it("stops and exposes the error when the scan cannot be loaded", async () => {
    getScan.mockRejectedValue(new Error("not found"));
    const { result } = renderHook(() => useScanRecord("missing"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(SCAN_POLL_MS * 3);
    });
    expect(result.current.error).toBe("not found");
    expect(getScan).toHaveBeenCalledTimes(1);
  });

  describe("verdict-first report polling", () => {
    // act() defers renders to its end, so flush the first load before moving the
    // clock; otherwise the report effect starts after the time has already passed.
    const flush = () =>
      act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
    const pending = { ...base, status: "COMPLETE", report_status: "PENDING" };
    const ready = { ...base, status: "COMPLETE", report_status: "READY" };

    it("keeps polling after COMPLETE while the report is PENDING, then stops at READY", async () => {
      getScan
        .mockResolvedValueOnce(pending)
        .mockResolvedValueOnce(pending)
        .mockResolvedValue(ready);
      const { result } = renderHook(() => useScanRecord("s-1"));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      // The verdict is available at once, report still pending.
      expect(result.current.record?.report_status).toBe("PENDING");
      await act(async () => {
        await vi.advanceTimersByTimeAsync(REPORT_POLL_MS * 4);
      });
      expect(result.current.record?.report_status).toBe("READY");
      const calls = getScan.mock.calls.length;
      expect(calls).toBe(3);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(getScan).toHaveBeenCalledTimes(calls);
    });

    it("stops when the report FAILED", async () => {
      getScan
        .mockResolvedValueOnce(pending)
        .mockResolvedValue({ ...base, status: "COMPLETE", report_status: "FAILED" });
      const { result } = renderHook(() => useScanRecord("s-1"));
      await flush();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(REPORT_POLL_MS * 2);
      });
      expect(result.current.record?.report_status).toBe("FAILED");
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(getScan).toHaveBeenCalledTimes(2);
    });

    it("does not poll again for a legacy record without report_status", async () => {
      getScan.mockResolvedValue({ ...base, status: "COMPLETE" });
      renderHook(() => useScanRecord("s-1"));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(getScan).toHaveBeenCalledTimes(1);
    });

    it("backs off between report polls", () => {
      expect(nextReportDelay(3000)).toBe(4500);
      expect(nextReportDelay(9000)).toBe(10_000);
      expect(nextReportDelay(10_000)).toBe(10_000);
    });

    it("keeps the verdict through a failed report poll and retries", async () => {
      getScan
        .mockResolvedValueOnce(pending)
        .mockRejectedValueOnce(new Error("503"))
        .mockResolvedValue(ready);
      const { result } = renderHook(() => useScanRecord("s-1"));
      await flush();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(REPORT_POLL_MS * 5);
      });
      expect(result.current.error).toBeNull();
      expect(result.current.record?.report_status).toBe("READY");
    });

    it("gives up after the cap, says so, and can check again", async () => {
      getScan.mockResolvedValue(pending);
      const { result } = renderHook(() => useScanRecord("s-1"));
      await flush();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(REPORT_POLL_CAP_MS + 30_000);
      });
      expect(result.current.reportTimedOut).toBe(true);
      const stopped = getScan.mock.calls.length;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(getScan).toHaveBeenCalledTimes(stopped);
      act(() => result.current.checkReportAgain());
      await act(async () => {
        await vi.advanceTimersByTimeAsync(REPORT_POLL_MS + 100);
      });
      expect(result.current.reportTimedOut).toBe(false);
      expect(getScan.mock.calls.length).toBeGreaterThan(stopped);
    });
  });
});
