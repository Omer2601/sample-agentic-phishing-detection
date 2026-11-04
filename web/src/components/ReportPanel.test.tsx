// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ReportPanel } from "./ReportPanel";

const REPORT = [
  "## Verdict",
  "Phishing, risk 95, block.",
  "## Reasoning",
  "url_analyst found a typosquat. I weighed code_analyst most.",
  "## Evidence",
  "- url_analyst: typosquat.",
  "## Recommended actions",
  "### For the recipient",
  "- Do not sign in.",
  "- Report the message.",
  "### For the security team",
  "- Block `g00gle[.]com`.",
  "## Gaps",
  "None. <img src=x onerror=alert(1)> [click](https://evil.example)",
].join("\n");

describe("ReportPanel", () => {
  it("renders sections as headings and actions as lists", () => {
    render(<ReportPanel report={REPORT} scanId="abcdef123456" />);
    expect(screen.getByRole("heading", { name: "Reasoning" })).toBeTruthy();
    expect(
      screen.getByRole("heading", { name: "Recommended actions" }),
    ).toBeTruthy();
    const recipient = screen.getByRole("list", { name: "For the recipient" });
    expect(within(recipient).getAllByRole("listitem")).toHaveLength(2);
    const team = screen.getByRole("list", { name: "For the security team" });
    expect(within(team).getByText("g00gle[.]com").tagName).toBe("CODE");
  });

  it("never turns report text into links or markup", () => {
    const { container } = render(
      <ReportPanel report={REPORT} scanId="abcdef123456" />,
    );
    expect(container.querySelector("a")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeTruthy();
  });

  it("shows the verbatim Markdown on request", () => {
    const { container } = render(
      <ReportPanel report={REPORT} scanId="abcdef123456" />,
    );
    expect(container.querySelector("pre")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Markdown/ }));
    expect(container.querySelector("pre")?.textContent).toBe(REPORT);
  });

  it("has no banner of its own (the AppShell shows the single persistent one)", () => {
    render(<ReportPanel report={REPORT} scanId="abcdef123456" />);
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("includes the disclaimer in the copied Markdown", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    render(<ReportPanel report={REPORT} scanId="abcdef123456" />);
    fireEvent.click(screen.getByRole("button", { name: /Copy/ }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const copied = writeText.mock.calls[0][0] as string;
    expect(copied.startsWith("**AI-generated analysis: human review required.**")).toBe(true);
    expect(copied.endsWith("any action is taken.")).toBe(true);
    expect(copied).toContain(REPORT);
  });

  it("shows the whole report, with no fixed-height scroll box to cut it off", () => {
    const { container } = render(
      <ReportPanel report={REPORT} scanId="abcdef123456" />,
    );
    const clipped = (root: Element) =>
      Array.from(root.querySelectorAll<HTMLElement>("*")).filter((el) =>
        /(^|\s)(max-h-\S+|overflow-(auto|scroll|y-auto|y-scroll|hidden))(\s|$)/.test(
          el.className,
        ),
      );
    expect(clipped(container)).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: /Markdown/ }));
    expect(clipped(container)).toEqual([]);
  });
});
