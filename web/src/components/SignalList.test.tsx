// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import type { Finding, Signal } from "@/lib/types";
import { SignalList } from "./SignalList";

function finding(signals: Signal[]): Finding {
  return {
    agent: "code_analyst",
    status: "ok",
    verdict: "suspicious",
    confidence: 60,
    signals,
    artifacts: [],
    usage: { input_tokens: 1, output_tokens: 1, model_id: "m" },
    latency_ms: 1,
    calls: [],
  };
}

describe("SignalList", () => {
  it("shows the catalog title and explanation instead of the raw name, then the evidence", () => {
    render(
      <SignalList
        finding={finding([
          {
            name: "blocked_by_browser",
            severity: "low",
            evidence: "net::ERR_BLOCKED_BY_CLIENT",
          },
        ])}
      />,
    );
    expect(
      screen.getByText("The isolated browser refused to open this URL"),
    ).toBeTruthy();
    // The explanation is visible text, not a tooltip.
    expect(screen.getByText(/not evidence of phishing/)).toBeTruthy();
    expect(screen.getByText("net::ERR_BLOCKED_BY_CLIENT")).toBeTruthy();
    expect(screen.queryByText("blocked_by_browser")).toBeNull();
    expect(screen.getByText("low")).toBeTruthy();
  });

  it("humanizes a name the catalog does not know", () => {
    render(
      <SignalList
        finding={finding([
          {
            name: "zz_made_up_model_signal",
            severity: "medium",
            evidence: "inline: eval(",
          },
        ])}
      />,
    );
    expect(screen.getByText("Zz made up model signal")).toBeTruthy();
    expect(screen.getByText("inline: eval(")).toBeTruthy();
  });

  it("keeps the most severe signal first", () => {
    render(
      <SignalList
        finding={finding([
          { name: "a_low_one", severity: "low", evidence: "x" },
          { name: "a_critical_one", severity: "critical", evidence: "y" },
          { name: "a_medium_one", severity: "medium", evidence: "z" },
        ])}
      />,
    );
    const items = screen
      .getAllByRole("listitem")
      .map((li) => li.textContent ?? "");
    expect(items[0]).toContain("A critical one");
    expect(items[1]).toContain("A medium one");
    expect(items[2]).toContain("A low one");
  });
});
