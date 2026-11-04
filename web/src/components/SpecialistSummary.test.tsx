// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { Finding, Verdict } from "@/lib/types";
import { SpecialistSummary } from "./SpecialistSummary";

const usage = { input_tokens: 1, output_tokens: 1, model_id: "m" };
const findings: Finding[] = [
  {
    agent: "url_analyst",
    status: "ok",
    verdict: "phishing",
    confidence: 92,
    signals: [
      { name: "Low severity hint", severity: "low", evidence: "minor" },
      {
        name: "Typosquat of google.com",
        severity: "critical",
        evidence: "g00gle uses zeros",
      },
    ],
    artifacts: [],
    usage,
    latency_ms: 4200,
    calls: [],
  },
  {
    agent: "code_analyst",
    status: "blocked_by_guardrail",
    verdict: "unknown",
    confidence: 0,
    signals: [],
    artifacts: [],
    usage,
    latency_ms: 1,
    calls: [],
  },
];
const verdict: Verdict = {
  verdict: "phishing",
  risk_score: 90,
  confidence: "high",
  action: "block",
  summary: "s",
  disagreements: [
    "Brand and visual found no logo while the URL analyst saw a typosquat.",
  ],
  missed_by_specialists: ["Form posts to a Telegram bot endpoint."],
  report_markdown: "# r",
};

function section(name: string) {
  return screen.getByRole("region", { name });
}

describe("SpecialistSummary", () => {
  it("shows one section per specialist, including one that did not report", () => {
    render(<SpecialistSummary findings={findings} verdict={verdict} />);
    expect(section("URL analyst")).toBeTruthy();
    expect(section("Brand and visual")).toBeTruthy();
    expect(section("Code analyst")).toBeTruthy();
    expect(within(section("Brand and visual")).getByText("No report")).toBeTruthy();
  });

  it("gives each reporting specialist its verdict, confidence, latency and signals", () => {
    render(<SpecialistSummary findings={findings} verdict={verdict} />);
    const url = within(section("URL analyst"));
    expect(url.getByText("Phishing")).toBeTruthy();
    expect(url.getByText("92% confident")).toBeTruthy();
    expect(url.getByText("4s")).toBeTruthy();
    const names = url.getAllByRole("listitem").map((li) => li.textContent ?? "");
    expect(names[0]).toContain("Typosquat of google.com");
    expect(names[0]).toContain("g00gle uses zeros");
    expect(names[1]).toContain("Low severity hint");
  });

  it("shows Error 404, not Unknown, for a specialist whose target was a 404", () => {
    const notFound: Finding[] = [
      { ...findings[0], agent: "url_analyst", verdict: "error_404", signals: [] },
    ];
    render(<SpecialistSummary findings={notFound} verdict={verdict} />);
    const url = within(section("URL analyst"));
    expect(url.getByText("Error 404")).toBeTruthy();
    expect(url.queryByText("Unknown")).toBeNull();
  });

  it("shows the capture note as plain text in the specialist's section", () => {
    const noted: Finding[] = [
      {
        ...findings[0],
        agent: "brand_visual",
        capture_note:
          "A bot check (Cloudflare) did not clear within 15 s, so no page content was captured.",
      },
    ];
    render(<SpecialistSummary findings={noted} verdict={verdict} />);
    expect(
      within(section("Brand and visual")).getByText(/did not clear within 15 s/),
    ).toBeTruthy();
    expect(within(section("URL analyst")).queryByText(/did not clear/)).toBeNull();
  });

  it("marks a guardrail block as a signal, not a crash", () => {
    render(<SpecialistSummary findings={findings} verdict={verdict} />);
    expect(
      within(section("Code analyst")).getByText("Blocked by guardrail"),
    ).toBeTruthy();
    expect(
      within(section("Code analyst")).getByText("No signals recorded."),
    ).toBeTruthy();
  });

  it("surfaces the orchestrator's quality notes", () => {
    render(<SpecialistSummary findings={findings} verdict={verdict} />);
    expect(screen.getByText(/Telegram bot endpoint/)).toBeTruthy();
    expect(screen.getByText(/saw a typosquat/)).toBeTruthy();
  });
});
