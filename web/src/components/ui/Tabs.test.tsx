// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Tabs } from "./Tabs";

describe("Tabs", () => {
  it("labels the tablist from the label prop", () => {
    render(
      <Tabs
        label="Example views"
        items={[
          { id: "a", label: "A", content: <p>a</p> },
          { id: "b", label: "B", content: <p>b</p> },
        ]}
      />,
    );
    expect(screen.getByRole("tablist", { name: "Example views" })).toBeTruthy();
  });
});
