// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { LEGACY_STORAGE_KEY, STORAGE_KEY, ThemeProvider, useTheme } from "./useTheme";

function Probe() {
  const { theme } = useTheme();
  return <p data-testid="theme">{theme}</p>;
}

function renderProbe() {
  render(
    <ThemeProvider>
      <Probe />
    </ThemeProvider>,
  );
  return screen.getByTestId("theme").textContent;
}

describe("useTheme storage", () => {
  afterEach(() => window.localStorage.clear());

  it("uses a neutral storage key", () => {
    expect(STORAGE_KEY).toBe("ui-theme");
  });

  it("migrates the legacy key once: reads it, writes the new key, removes the old one", () => {
    window.localStorage.setItem(LEGACY_STORAGE_KEY, "light");
    expect(renderProbe()).toBe("light");
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("light");
    expect(window.localStorage.getItem(LEGACY_STORAGE_KEY)).toBeNull();
  });

  it("prefers the new key over a leftover legacy value", () => {
    window.localStorage.setItem(STORAGE_KEY, "dark");
    window.localStorage.setItem(LEGACY_STORAGE_KEY, "light");
    expect(renderProbe()).toBe("dark");
    expect(window.localStorage.getItem(LEGACY_STORAGE_KEY)).toBeNull();
  });
});
