// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { parseSimilarSummary } from "./similarScan";

describe("parseSimilarSummary", () => {
  it("accepts the error_404 verdict", () => {
    expect(
      parseSimilarSummary("hxxps://a[.]example/ | verdict=error_404 | risk=0")
        ?.verdict,
    ).toBe("error_404");
  });

  it("accepts the site_down verdict", () => {
    expect(
      parseSimilarSummary("hxxp://gone[.]example/ | verdict=site_down | risk=10")
        ?.verdict,
    ).toBe("site_down");
  });

  it("splits the stored line into URL, verdict, risk and reason", () => {
    expect(
      parseSimilarSummary(
        "hxxps://evil2[.]example/ | verdict=phishing | risk=90 | reason: fake bank login",
      ),
    ).toEqual({
      url: "hxxps://evil2[.]example/",
      verdict: "phishing",
      risk: 90,
      reason: "fake bank login",
    });
  });

  it("keeps a reason that itself contains the separator", () => {
    const parsed = parseSimilarSummary(
      "hxxp://a[.]example | verdict=suspicious | risk=55 | reason: login | brand lure",
    );
    expect(parsed?.reason).toBe("login | brand lure");
    expect(parsed?.verdict).toBe("suspicious");
  });

  it("accepts a line without risk or reason", () => {
    expect(parseSimilarSummary("hxxps://a[.]example/ | verdict=legitimate")).toEqual({
      url: "hxxps://a[.]example/",
      verdict: "legitimate",
      risk: null,
      reason: null,
    });
  });

  it("returns null for text that is not a summary line", () => {
    expect(parseSimilarSummary("free text")).toBeNull();
    expect(parseSimilarSummary("hxxps://a[.]example/ | verdict=maybe | risk=5")).toBeNull();
    expect(parseSimilarSummary(" | verdict=phishing")).toBeNull();
  });

  it("drops a risk outside 0 to 100", () => {
    expect(
      parseSimilarSummary("hxxps://a[.]example/ | verdict=phishing | risk=900")?.risk,
    ).toBeNull();
  });
});
