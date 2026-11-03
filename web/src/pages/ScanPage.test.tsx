// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const startScan = vi.fn();
vi.mock("@/lib/api", () => ({
  api: {
    startScan: (...a: unknown[]) => startScan(...a),
    getSuggestions: vi.fn(async () => ({
      items: [],
      groups: [],
      attribution: "",
      liveCount: 0,
      cached: false,
      warning: "",
    })),
  },
}));

import { ScanPage } from "./ScanPage";

describe("ScanPage", () => {
  it("submits and moves to the result route so the scan survives navigation", async () => {
    startScan.mockResolvedValue({ scan_id: "s-42" });
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/" element={<ScanPage />} />
          <Route path="/results/:scanId" element={<p>result page</p>} />
        </Routes>
      </MemoryRouter>,
    );
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "https://a.example" },
    });
    fireEvent.submit(
      screen.getByRole("textbox").closest("form") as HTMLFormElement,
    );
    await waitFor(() => expect(screen.getByText("result page")).toBeTruthy());
    expect(startScan).toHaveBeenCalledWith("https://a.example");
  });

  it("renders no page-level disclaimer banner (AppShell shows the single persistent one)", () => {
    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>,
    );
    expect(screen.queryByTestId("disclaimer-banner")).toBeNull();
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("states the v2 timing and the https default", () => {
    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>,
    );
    expect(screen.getByText(/about 30 to 40 seconds\. https:\/\/ is added/)).toBeTruthy();
  });
});
