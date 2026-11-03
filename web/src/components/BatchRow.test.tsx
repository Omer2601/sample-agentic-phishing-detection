// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/hooks/useTheme";
import type { BatchRecord } from "@/lib/types";
import { BatchRow } from "./BatchRow";

const NOW = Date.parse("2026-09-29T12:01:00Z");

function row(overrides: Partial<BatchRecord>) {
  const batch: BatchRecord = {
    batch_id: "b-1",
    source: "ui",
    total: 0,
    status_counts: {},
    verdict_counts: {},
    created_at: "2026-09-29T12:00:00Z",
    first_started_at: null,
    completed_at: null,
    wall_clock_ms: null,
    sum_scan_ms: 0,
    cost_usd: "0",
    awaiting_upload: false,
    split_at: null,
    error: null,
    ...overrides,
  };
  render(
    <ThemeProvider>
      <MemoryRouter>
        <BatchRow batch={batch} now={NOW} />
      </MemoryRouter>
    </ThemeProvider>,
  );
}

describe("BatchRow upload lifecycle", () => {
  it("says why a batch failed and does not show it as running", () => {
    row({
      completed_at: "2026-09-29T12:30:00Z",
      split_at: "2026-09-29T12:30:00Z",
      wall_clock_ms: 0,
      error: "CSV was never uploaded",
    });
    expect(screen.getByText(/CSV was never uploaded/)).toBeTruthy();
    expect(screen.queryByLabelText("Running")).toBeNull();
  });

  it("says a batch is waiting for its CSV while the upload is outstanding", () => {
    row({ awaiting_upload: true });
    expect(screen.getByText(/Waiting for the CSV upload/)).toBeTruthy();
  });
});
