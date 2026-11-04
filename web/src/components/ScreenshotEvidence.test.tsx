// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ScreenshotEvidence } from "./ScreenshotEvidence";

describe("ScreenshotEvidence caption", () => {
  it("does not point at a link when no screenshot was captured (UI e2e run 2, D7)", () => {
    render(<ScreenshotEvidence src={null} />);
    expect(screen.getByText("Screenshot unavailable")).toBeTruthy();
    expect(screen.queryByText(/link below/i)).toBeNull();
    expect(screen.queryByText(/expires/i)).toBeNull();
    expect(screen.getByText(/No screenshot was captured for this scan/)).toBeTruthy();
  });

  it("explains the expiring image link only when there is an image", () => {
    render(<ScreenshotEvidence src="https://example.invalid/shot.png" />);
    expect(screen.getByRole("img")).toBeTruthy();
    expect(screen.queryByText(/link below/i)).toBeNull();
    expect(screen.getByText(/image link expires after a few minutes/)).toBeTruthy();
  });

  it("shows the capture note under the screenshot as plain text", () => {
    render(
      <ScreenshotEvidence
        src={null}
        finding={{
          agent: "brand_visual",
          status: "ok",
          verdict: "phishing",
          confidence: 80,
          signals: [],
          artifacts: [],
          usage: { input_tokens: 1, output_tokens: 1, model_id: "m" },
          latency_ms: 1,
          calls: [],
          capture_note:
            "Cloudflare flagged this site as phishing; the warning was bypassed inside the isolated browser to capture the page.",
        }}
      />,
    );
    const note = screen.getByText(/the warning was bypassed/);
    expect(note.closest("figure")).toBeTruthy();
  });

  it("says the link expired when the presigned image fails to load", () => {
    render(<ScreenshotEvidence src="https://example.invalid/shot.png" />);
    fireEvent.error(screen.getByRole("img"));
    expect(screen.getByText(/link has expired/)).toBeTruthy();
    expect(screen.getByText(/Reload the page/)).toBeTruthy();
  });
});
