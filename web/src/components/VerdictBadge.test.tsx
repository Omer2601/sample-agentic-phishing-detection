// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { RiskPill, VerdictBadge } from "./VerdictBadge";

describe("VerdictBadge", () => {
  it.each([
    ["phishing", "Phishing"],
    ["suspicious", "Suspicious"],
    ["legitimate", "Legitimate"],
    ["unknown", "Unknown"],
    ["error_404", "Error 404"],
    ["site_down", "Site down"],
  ] as const)("labels %s with text, not colour alone", (verdict, label) => {
    render(<VerdictBadge verdict={verdict} />);
    expect(screen.getByText(label)).toBeTruthy();
  });

  it("does not show Unknown for a 404", () => {
    render(<VerdictBadge verdict="error_404" />);
    expect(screen.queryByText("Unknown")).toBeNull();
  });

  it("shows the risk out of 100", () => {
    render(<RiskPill score={87} />);
    expect(screen.getByText("87")).toBeTruthy();
    expect(screen.getByText("/100")).toBeTruthy();
  });
});
