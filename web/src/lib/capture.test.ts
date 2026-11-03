// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import type { Finding, Verdict } from "./types";
import { pageObserved, redirectChain } from "./capture";

const usage = { input_tokens: 1, output_tokens: 1, model_id: "m" };
function f(agent: Finding["agent"], over: Partial<Finding> = {}): Finding {
  return {
    agent,
    status: "ok",
    verdict: "suspicious",
    confidence: 50,
    signals: [],
    artifacts: [],
    usage,
    latency_ms: 1,
    calls: [],
    ...over,
  };
}
const verdict: Verdict = {
  verdict: "suspicious",
  risk_score: 69,
  confidence: "medium",
  action: "warn",
  summary: "s",
  disagreements: [],
  missed_by_specialists: [],
  report_markdown: "",
};

describe("pageObserved", () => {
  it("prefers the verdict's own field", () => {
    expect(pageObserved({ ...verdict, page_observed: false }, [])).toBe(false);
    expect(
      pageObserved({ ...verdict, page_observed: true }, [
        f("brand_visual", { page_observed: false }),
      ]),
    ).toBe(true);
  });

  it("falls back to the browser findings, and is null when nothing says", () => {
    const unseen = [
      f("brand_visual", { page_observed: false }),
      f("code_analyst", { page_observed: false }),
      f("url_analyst", { page_observed: true }),
    ];
    expect(pageObserved(verdict, unseen)).toBe(false);
    expect(
      pageObserved(verdict, [
        ...unseen,
        f("code_analyst", { page_observed: true }),
      ]),
    ).toBe(true);
    expect(pageObserved(verdict, [f("url_analyst")])).toBeNull();
    expect(pageObserved(null, [])).toBeNull();
  });
});

describe("redirectChain", () => {
  it("prefers the browser chain and ignores single hops", () => {
    const http = [{ url: "https://a.example/" }, { url: "https://b.example/" }];
    const browser = [...http, { url: "https://c.example/", via: "client" }];
    expect(
      redirectChain([
        f("url_analyst", { redirect_chain: http }),
        f("brand_visual", { redirect_chain: browser }),
      ]),
    ).toEqual({ agent: "brand_visual", hops: browser });
    expect(
      redirectChain([
        f("brand_visual", { redirect_chain: [{ url: "https://a.example/" }] }),
        f("url_analyst", { redirect_chain: http }),
      ])?.agent,
    ).toBe("url_analyst");
    expect(redirectChain([f("code_analyst")])).toBeNull();
  });
});
