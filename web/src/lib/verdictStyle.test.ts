// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import {
  CHART_VERDICTS,
  CONFIDENCE_STYLE,
  VERDICT_STYLE,
  chartColor,
  seriesColor,
} from "./verdictStyle";
import { SPECIALISTS } from "./types";

describe("verdict styling", () => {
  it("covers every verdict label", () => {
    expect(Object.keys(VERDICT_STYLE).sort()).toEqual([
      "error_404",
      "legitimate",
      "phishing",
      "site_down",
      "suspicious",
      "unknown",
    ]);
  });

  it("labels site_down as Site down, neutral and never a chart series", () => {
    expect(VERDICT_STYLE.site_down.label).toBe("Site down");
    expect(VERDICT_STYLE.site_down.token).toBe("neutral");
    expect(VERDICT_STYLE.site_down.chart).toBeNull();
    expect(CHART_VERDICTS as readonly string[]).not.toContain("site_down");
  });

  it("labels error_404 as Error 404, neutral and never a chart series", () => {
    expect(VERDICT_STYLE.error_404.label).toBe("Error 404");
    expect(VERDICT_STYLE.error_404.token).toBe("neutral");
    expect(VERDICT_STYLE.error_404.chart).toBeNull();
    expect(CHART_VERDICTS as readonly string[]).not.toContain("error_404");
    expect(VERDICT_STYLE.error_404.label).not.toBe(VERDICT_STYLE.unknown.label);
  });

  it("charts only the three decisive verdicts, in stack order", () => {
    expect(CHART_VERDICTS).toEqual(["phishing", "suspicious", "legitimate"]);
  });

  it("uses the validated palette per theme", () => {
    expect(chartColor("phishing", "light")).toBe("#d03b3b");
    expect(chartColor("suspicious", "light")).toBe("#eda100");
    expect(chartColor("legitimate", "light")).toBe("#2a78d6");
    expect(chartColor("suspicious", "dark")).toBe("#c98500");
    expect(chartColor("legitimate", "dark")).toBe("#3987e5");
  });

  it("assigns categorical series in fixed order and never cycles", () => {
    expect(seriesColor(0, "light")).toBe("#2a78d6");
    expect(seriesColor(1, "dark")).toBe("#d95926");
    expect(() => seriesColor(2, "light")).toThrow(/fold/);
  });

  it("maps confidence bands to meter dots", () => {
    expect(CONFIDENCE_STYLE.high.dots).toBe(3);
    expect(CONFIDENCE_STYLE.low.dots).toBe(1);
  });

  it("lists the three specialists", () => {
    expect(SPECIALISTS).toEqual([
      "url_analyst",
      "brand_visual",
      "code_analyst",
    ]);
  });
});
