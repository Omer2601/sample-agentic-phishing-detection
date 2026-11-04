// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ApiConsolePage } from "./ApiConsolePage";

describe("ApiConsolePage", () => {
  it("renders no page-level disclaimer banner (AppShell shows the single persistent one)", () => {
    render(
      <MemoryRouter>
        <ApiConsolePage />
      </MemoryRouter>,
    );
    expect(screen.queryByTestId("disclaimer-banner")).toBeNull();
  });

  it("puts the typed id into the scan and batch paths", () => {
    const { container } = render(
      <MemoryRouter>
        <ApiConsolePage />
      </MemoryRouter>,
    );
    fireEvent.change(screen.getByLabelText("Scan id"), {
      target: { value: "s-9" },
    });
    fireEvent.change(screen.getByLabelText("Batch id"), {
      target: { value: "b-7" },
    });
    expect(container.textContent).toContain("/scans/s-9");
    expect(container.textContent).toContain("/batches/b-7");
  });

  it("documents the v2 routes only", () => {
    const { container } = render(
      <MemoryRouter>
        <ApiConsolePage />
      </MemoryRouter>,
    );
    expect(container.textContent).not.toContain("/scan/batch");
    expect(container.textContent).not.toContain("job_id");
  });
});
