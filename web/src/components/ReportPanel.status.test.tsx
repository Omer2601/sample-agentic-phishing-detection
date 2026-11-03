// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  elapsedSecondsSince,
  REPORT_FAILED_TEXT,
  REPORT_PENDING_TEXT,
  REPORT_PENDING_TITLE,
} from "@/lib/reportCopy";
import { ReportPanel } from "./ReportPanel";

const NOW = Date.parse("2026-10-05T12:00:30Z");

function mockReducedMotion(matches: boolean) {
  vi.stubGlobal(
    "matchMedia",
    (query: string) => ({
      matches,
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {},
    }),
  );
  window.matchMedia = globalThis.matchMedia;
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  mockReducedMotion(false);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  // @ts-expect-error jsdom has no matchMedia; restore that.
  delete window.matchMedia;
});

describe("ReportPanel status", () => {
  it("shows an accessible placeholder while the report is PENDING", () => {
    render(
      <ReportPanel
        report=""
        scanId="abcdef123456"
        status="PENDING"
        startedAt="2026-10-05T12:00:00Z"
      />,
    );
    const status = screen.getByRole("status");
    expect(status.getAttribute("aria-busy")).toBe("true");
    expect(screen.getByText(REPORT_PENDING_TITLE)).toBeTruthy();
    expect(screen.getByText(REPORT_PENDING_TEXT)).toBeTruthy();
    expect(screen.getByText("30s elapsed")).toBeTruthy();
    expect(screen.getByTestId("report-skeleton")).toBeTruthy();
  });

  it("never claims a percentage on the progress bar", () => {
    render(<ReportPanel report="" scanId="s" status="PENDING" />);
    const bar = screen.getByRole("progressbar");
    expect(bar.hasAttribute("aria-valuenow")).toBe(false);
    expect(bar.textContent).not.toMatch(/%/);
  });

  it("ticks the elapsed counter every second", async () => {
    render(
      <ReportPanel
        report=""
        scanId="s"
        status="PENDING"
        startedAt="2026-10-05T12:00:00Z"
      />,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(screen.getByText("33s elapsed")).toBeTruthy();
  });

  it("disables Copy and Download .md with a reason while PENDING", () => {
    render(<ReportPanel report="" scanId="s" status="PENDING" />);
    for (const name of [/^Copy/, /^Download \.md/]) {
      const button = screen.getByRole("button", { name });
      expect((button as HTMLButtonElement).disabled).toBe(true);
      expect(button.getAttribute("aria-label")).toContain(
        "Available when the report is ready",
      );
    }
  });

  it("uses a static bar and no shimmer under prefers-reduced-motion", () => {
    mockReducedMotion(true);
    const { container } = render(
      <ReportPanel report="" scanId="s" status="PENDING" />,
    );
    expect(screen.getByRole("progressbar").getAttribute("data-motion")).toBe(
      "static",
    );
    expect(container.querySelector(".skeleton")).toBeNull();
  });

  it("animates the bar when motion is allowed", () => {
    const { container } = render(
      <ReportPanel report="" scanId="s" status="PENDING" />,
    );
    expect(screen.getByRole("progressbar").getAttribute("data-motion")).toBe(
      "animated",
    );
    expect(container.querySelector(".skeleton")).not.toBeNull();
  });

  it("says so, stops the clock and offers another check after a timeout", () => {
    const again = vi.fn();
    render(
      <ReportPanel
        report=""
        scanId="s"
        status="PENDING"
        timedOut
        onCheckAgain={again}
      />,
    );
    expect(screen.getByText(/taking longer than expected/)).toBeTruthy();
    expect(screen.getByRole("status").getAttribute("aria-busy")).toBe("false");
    screen.getByRole("button", { name: "Check again" }).click();
    expect(again).toHaveBeenCalledTimes(1);
  });

  it("shows the failure message, the reason and the disclaimer when FAILED", () => {
    render(
      <ReportPanel
        report=""
        scanId="s"
        status="FAILED"
        error="Model throttled"
      />,
    );
    expect(screen.getByText(REPORT_FAILED_TEXT)).toBeTruthy();
    expect(screen.getByText(/Model throttled/)).toBeTruthy();
    expect(screen.getByText(/human review required/i)).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("omits the reason line when FAILED has no report_error", () => {
    render(<ReportPanel report="" scanId="s" status="FAILED" error="  " />);
    expect(screen.queryByText(/Reason:/)).toBeNull();
  });

  it("renders the report as before when READY, and when the status is absent", () => {
    const { rerender } = render(
      <ReportPanel report={"## Verdict\nPhishing"} scanId="s" status="READY" />,
    );
    expect(screen.getByRole("heading", { name: "Verdict" })).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
    rerender(<ReportPanel report={"## Verdict\nPhishing"} scanId="s" />);
    expect(screen.getByRole("heading", { name: "Verdict" })).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: /Download \.md/ }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });
});

describe("elapsedSecondsSince", () => {
  it("clamps skew and bad input to a sane number", () => {
    expect(elapsedSecondsSince("2026-10-05T12:00:00Z", NOW, 0)).toBe(30);
    expect(elapsedSecondsSince("2030-01-01T00:00:00Z", NOW, 0)).toBe(0);
    expect(elapsedSecondsSince("garbage", NOW, NOW - 5000)).toBe(5);
    expect(elapsedSecondsSince(null, NOW, NOW - 2000)).toBe(2);
  });
});
