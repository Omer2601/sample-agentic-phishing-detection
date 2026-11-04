// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { SimilarScan } from "@/lib/types";
import { SimilarScans } from "./SimilarScans";

const PAST: SimilarScan = {
  scan_id: "a-old",
  summary: "hxxps://evil2[.]example/ | verdict=phishing | risk=90 | reason: fake bank login",
};

function show(scans: SimilarScan[] | undefined) {
  return render(
    <MemoryRouter>
      <SimilarScans scans={scans} />
    </MemoryRouter>,
  );
}

describe("SimilarScans", () => {
  it("lists your past scans, links each to its result and says they are not evidence", () => {
    show([PAST]);
    expect(screen.getByRole("list", { name: "Similar past scans" })).toBeTruthy();
    const row = screen.getByRole("listitem");
    expect(row.textContent).not.toContain("verdict=");
    expect(row.textContent).not.toContain("risk=");
    expect(screen.getByText("hxxps://evil2[.]example/")).toBeTruthy();
    expect(row.querySelector('[data-verdict="phishing"]')?.textContent).toContain(
      "Phishing",
    );
    expect(row.querySelector("[data-risk]")?.textContent).toContain("90");
    expect(screen.getByText("fake bank login")).toBeTruthy();
    expect(screen.getByText(/not evidence for this URL/)).toBeTruthy();
    expect(screen.getByText(/only your own scans/)).toBeTruthy();
    const link = screen.getByRole("link", { name: /Open scan/ });
    expect(link.getAttribute("href")).toBe("/results/a-old");
  });

  it("renders nothing without past scans", () => {
    expect(show([]).container.innerHTML).toBe("");
    expect(show(undefined).container.innerHTML).toBe("");
  });

  it("falls back to the stored text when it is not a summary line", () => {
    show([{ scan_id: "a-old", summary: "older free-text note" }]);
    expect(screen.getByText("older free-text note")).toBeTruthy();
    expect(document.querySelector("[data-verdict]")).toBeNull();
  });

  it("shows stored text as text, never as markup", () => {
    show([{ scan_id: "a-old", summary: '<a href="https://x.example">click</a>' }]);
    expect(screen.getAllByRole("link")).toHaveLength(1);
    expect(screen.getByText('<a href="https://x.example">click</a>')).toBeTruthy();
  });
});
