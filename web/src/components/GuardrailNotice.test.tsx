// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GuardrailNotice } from "./GuardrailNotice";

describe("GuardrailNotice", () => {
  it("renders nothing without events", () => {
    const { container } = render(<GuardrailNotice events={[]} />);
    expect(container.textContent).toBe("");
  });

  it("explains each event as a signal, never a drop", () => {
    render(
      <GuardrailNotice
        events={["input_guardrail_intervened", "some_future_event"]}
      />,
    );
    expect(screen.getByText(/It was still scanned/)).toBeTruthy();
    // An unknown event is shown verbatim rather than hidden.
    expect(screen.getByText("some_future_event")).toBeTruthy();
  });
});
