// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/hooks/useTheme";
import { WelcomePage } from "./WelcomePage";

describe("WelcomePage", () => {
  it("does not claim MFA is required (the default is optional TOTP)", () => {
    render(
      <ThemeProvider>
        <MemoryRouter>
          <WelcomePage />
        </MemoryRouter>
      </ThemeProvider>,
    );
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/requires? (an authenticator|multi-factor|MFA)/i);
    expect(screen.getByRole("link", { name: "Sign in" })).toBeTruthy();
  });
});
