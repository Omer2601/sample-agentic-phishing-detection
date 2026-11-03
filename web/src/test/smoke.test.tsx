// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

describe("test tooling", () => {
  it("renders into jsdom", () => {
    render(<p>ready</p>);
    expect(screen.getByText("ready")).toBeTruthy();
  });

  it("has a ResizeObserver for Recharts", () => {
    expect(typeof globalThis.ResizeObserver).toBe("function");
  });
});
