// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ChartCard } from "./ChartCard";

describe("ChartCard", () => {
  it("switches between the chart and an accessible table view", () => {
    render(
      <ChartCard
        title="Scans per day"
        table={{ columns: ["Day", "Phishing"], rows: [["Sep 29", 38]] }}
      >
        <div>chart body</div>
      </ChartCard>,
    );
    expect(screen.getByText("chart body")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Table" }));
    expect(screen.getByRole("table")).toBeTruthy();
    expect(screen.getByText("38")).toBeTruthy();
    expect(
      screen
        .getByRole("button", { name: "Table" })
        .getAttribute("aria-pressed"),
    ).toBe("true");
  });
});
