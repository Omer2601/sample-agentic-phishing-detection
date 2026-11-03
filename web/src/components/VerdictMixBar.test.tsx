// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ThemeProvider } from "@/hooks/useTheme";
import { VerdictMixBar } from "./VerdictMixBar";

describe("VerdictMixBar", () => {
  it("states the mix in text so colour is not the only cue", () => {
    render(
      <ThemeProvider>
        <VerdictMixBar
          counts={{ phishing: 38, suspicious: 6, legitimate: 3 }}
          total={50}
        />
      </ThemeProvider>,
    );
    expect(
      screen.getByText("38 phishing, 6 suspicious, 3 legitimate"),
    ).toBeTruthy();
  });

  it("names Error 404 and Site down scans in the text line", () => {
    render(
      <ThemeProvider>
        <VerdictMixBar
          counts={{ phishing: 1, error_404: 2, site_down: 3 }}
          total={6}
        />
      </ThemeProvider>,
    );
    expect(
      screen.getByText("1 phishing, 2 error 404, 3 site down"),
    ).toBeTruthy();
  });
});
