// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

/*
 * WCAG 2.x contrast for the light theme's warn token, read from index.css so
 * the check follows the real value. text-warn sits on plain surfaces and on
 * bg-warn/15 chips; both must reach 4.5:1 for normal-size text.
 */
type Rgb = [number, number, number];

const css = readFileSync(path.resolve(__dirname, "../index.css"), "utf8");
const lightBlock = css.slice(css.indexOf(":root {"), css.indexOf(".dark {"));

function token(name: string): Rgb {
  const m = new RegExp(`--${name}:\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)`).exec(lightBlock);
  if (!m) throw new Error(`--${name} not found in the light theme`);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function luminance([r, g, b]: Rgb): number {
  const lin = (c: number) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

function over(fg: Rgb, alpha: number, bg: Rgb): Rgb {
  return fg.map((c, i) => c * alpha + bg[i] * (1 - alpha)) as Rgb;
}

describe("light theme warn text contrast", () => {
  const warn = token("warn");
  const white: Rgb = [255, 255, 255];

  it("reaches 4.5:1 on white", () => {
    expect(contrast(warn, white)).toBeGreaterThanOrEqual(4.5);
  });

  it("reaches 4.5:1 on a bg-warn/15 chip over white and over the page background", () => {
    expect(contrast(warn, over(warn, 0.15, white))).toBeGreaterThanOrEqual(4.5);
    expect(contrast(warn, over(warn, 0.15, token("bg")))).toBeGreaterThanOrEqual(4.5);
  });
});
