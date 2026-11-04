// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import type { Finding, Verdict } from "@/lib/types";
import { PageNotObservedNotice } from "./PageNotObservedNotice";

const usage = { input_tokens: 1, output_tokens: 1, model_id: "m" };
const verdict: Verdict = {
  verdict: "suspicious",
  risk_score: 69,
  confidence: "medium",
  action: "warn",
  summary: "Page not observed: a provider warning hid the real page.",
  disagreements: [],
  missed_by_specialists: [],
  report_markdown: "",
};
function brand(over: Partial<Finding> = {}): Finding {
  return {
    agent: "brand_visual",
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
const warning = {
  name: "cloudflare_malware_warning",
  severity: "high" as const,
  evidence: "Cloudflare.",
};

describe("PageNotObservedNotice", () => {
  it("renders nothing when the page was seen or nothing is known", () => {
    const seen = render(
      <PageNotObservedNotice
        verdict={{ ...verdict, page_observed: true }}
        findings={[]}
      />,
    );
    expect(seen.container.textContent).toBe("");
    const unknown = render(
      <PageNotObservedNotice verdict={verdict} findings={[]} />,
    );
    expect(unknown.container.textContent).toBe("");
  });

  it("says the verdict is held at Suspicious when a provider warning hid the page", () => {
    render(
      <PageNotObservedNotice
        verdict={{ ...verdict, page_observed: false }}
        findings={[brand({ page_observed: false, signals: [warning] })]}
      />,
    );
    const note = screen.getByRole("note", { name: "Page not observed" });
    expect(note.textContent).toContain("Page not observed.");
    expect(note.textContent).toContain("held at Suspicious at most");
  });

  it("explains other capture gaps without claiming a cap", () => {
    render(
      <PageNotObservedNotice
        verdict={verdict}
        findings={[brand({ page_observed: false })]}
      />,
    );
    const note = screen.getByRole("note", { name: "Page not observed" });
    expect(note.textContent).toContain("never saw the site's real page");
    expect(note.textContent).not.toContain("held at Suspicious");
  });

  it("says only the raw HTML was read when code_analyst fell back to it", () => {
    render(
      <PageNotObservedNotice
        verdict={{ ...verdict, page_observed: false }}
        findings={[
          brand({ page_observed: false }),
          brand({
            agent: "code_analyst",
            page_observed: false,
            signals: [
              { name: "static_html_only", severity: "low", evidence: "raw HTML" },
            ],
          }),
        ]}
      />,
    );
    const note = screen.getByRole("note", { name: "Page not observed" });
    expect(note.textContent).toContain("only its raw HTML was read");
    expect(note.textContent).toContain("scripts not run");
    expect(note.textContent).not.toContain("never saw");
  });

  it("says the bare host was captured when the certificate does not cover www.", () => {
    render(
      <PageNotObservedNotice
        verdict={{ ...verdict, page_observed: false }}
        findings={[
          brand({
            page_observed: false,
            signals: [
              { name: "tls_error", severity: "low", evidence: "Certificate name error." },
              { name: "www_sibling_capture", severity: "low", evidence: "Bare host." },
            ],
          }),
        ]}
      />,
    );
    const note = screen.getByRole("note", { name: "Page not observed" });
    expect(note.textContent).toContain(
      "The certificate does not cover the www. name, so the same site without www. was captured instead.",
    );
    expect(note.textContent).toContain("Visitors to this link see a certificate warning.");
    expect(note.textContent).toContain("held at Suspicious at most");
    expect(note.textContent).not.toContain("never saw");
  });
});
