// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { CodeInsights, Finding } from "@/lib/types";
import { CodeInsightsPanel } from "./CodeInsightsPanel";

const usage = { input_tokens: 1, output_tokens: 1, model_id: "m" };
function codeFinding(insights?: CodeInsights | null): Finding {
  return {
    agent: "code_analyst",
    status: "ok",
    verdict: "phishing",
    confidence: 90,
    signals: [],
    artifacts: [],
    usage,
    latency_ms: 1,
    calls: [],
    insights,
  };
}

const insights: CodeInsights = {
  endpoints: [
    {
      url: "hxxps://api[.]telegram[.]org/bot123/sendMessage",
      kind: "fetch",
      off_domain: true,
    },
    { url: "/static/app.js", kind: "xhr", off_domain: false },
  ],
  forms: [{ action: "", fields: ["email", "password"], submits_via_js: true }],
  script_count: 7,
  script_kb: 312,
  external_script_hosts: ["jsdelivr.net", "ipify.org"],
};

describe("CodeInsightsPanel", () => {
  it("renders nothing when the finding has no insights (older records)", () => {
    const { container: a } = render(
      <CodeInsightsPanel finding={codeFinding()} />,
    );
    expect(a.textContent).toBe("");
    const { container: b } = render(
      <CodeInsightsPanel finding={codeFinding(null)} />,
    );
    expect(b.textContent).toBe("");
    const { container: c } = render(<CodeInsightsPanel />);
    expect(c.textContent).toBe("");
  });

  it("says the page is only observed, never filled in", () => {
    render(<CodeInsightsPanel finding={codeFinding(insights)} />);
    expect(
      screen.getByRole("heading", { name: "What the page's code does" }),
    ).toBeTruthy();
    expect(
      screen.getByText(
        "Measured in the isolated browser; the page is observed, never filled in",
      ),
    ).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("marks off-domain and same-site endpoints in text", () => {
    render(<CodeInsightsPanel finding={codeFinding(insights)} />);
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3); // header + 2
    expect(rows[1].textContent).toContain("Off-domain");
    expect(rows[2].textContent).toContain("Same site");
  });

  it("lists forms, script totals and external script hosts", () => {
    render(<CodeInsightsPanel finding={codeFinding(insights)} />);
    expect(screen.getByText("No action (stays on the page)")).toBeTruthy();
    expect(screen.getByText("email, password")).toBeTruthy();
    expect(screen.getByText("Submitted by script")).toBeTruthy();
    expect(screen.getByText("7 scripts, 312 KB")).toBeTruthy();
    expect(screen.getByText("jsdelivr.net, ipify.org")).toBeTruthy();
  });

  it("copes with a form whose field list was omitted (contract default)", () => {
    render(
      <CodeInsightsPanel
        finding={codeFinding({ forms: [{ action: "/login", submits_via_js: false }] })}
      />,
    );
    expect(screen.getByText("none")).toBeTruthy();
  });

  it("renders page-derived text as plain text, never as links or markup", () => {
    const hostile: CodeInsights = {
      endpoints: [
        {
          url: "<img src=x onerror=alert(1)>https://evil.example/x",
          kind: "beacon",
          off_domain: true,
        },
      ],
      forms: [
        { action: "javascript:alert(1)", fields: [], submits_via_js: false },
      ],
      external_script_hosts: [],
    };
    const { container } = render(
      <CodeInsightsPanel finding={codeFinding(hostile)} />,
    );
    expect(container.querySelector("a")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    // Anything the backend missed is defanged on the way in.
    expect(container.textContent).toContain("hxxps://evil[.]example/x");
    expect(container.textContent).not.toContain("https://evil.example");
  });
});
