// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { Finding, RedirectHop } from "@/lib/types";
import { RedirectChainPanel } from "./RedirectChainPanel";

const usage = { input_tokens: 1, output_tokens: 1, model_id: "m" };
function brand(redirect_chain?: RedirectHop[]): Finding {
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
    redirect_chain,
  };
}

const chain: RedirectHop[] = [
  { url: "https://bit.ly/x", via: "start", status: 301, shortener: true },
  {
    url: "https://kit.pages.dev/",
    via: "http",
    status: 403,
    cross_domain: true,
    free_hosting: true,
  },
  {
    url: "https://kit.pages.dev/cdn-cgi/phish-bypass?atok=t",
    via: "warning_bypass",
  },
  {
    url: "https://dead.example/",
    via: "client",
    error: "net::ERR_NAME_NOT_RESOLVED",
  },
];

describe("RedirectChainPanel", () => {
  it("renders nothing without a chain of two hops or more (older records too)", () => {
    expect(
      render(<RedirectChainPanel findings={[brand()]} />).container.textContent,
    ).toBe("");
    expect(
      render(<RedirectChainPanel findings={[brand([chain[0]])]} />).container
        .textContent,
    ).toBe("");
  });

  it("lists every hop in order with how it was reached and its marks", () => {
    render(<RedirectChainPanel findings={[brand(chain)]} />);
    expect(
      screen.getByRole("heading", { name: "Redirect chain" }),
    ).toBeTruthy();
    expect(
      screen.getByText("4 hops, measured by Brand and visual"),
    ).toBeTruthy();
    const items = within(screen.getByRole("list")).getAllByRole("listitem");
    expect(items).toHaveLength(4);
    expect(items[0].textContent).toContain("1. Submitted URL");
    expect(items[0].textContent).toContain("Shortener");
    expect(items[1].textContent).toContain("HTTP 403");
    expect(items[1].textContent).toContain("New site");
    expect(items[1].textContent).toContain("Free hosting");
    expect(items[2].textContent).toContain("Proceeded past the warning");
    expect(items[3].textContent).toContain("Did not load");
    expect(items[3].textContent).toContain("net::ERR_NAME_NOT_RESOLVED");
  });

  it("shows URLs defanged as plain text, never as links or markup", () => {
    const hostile = [
      { url: "https://a.example/" },
      {
        url: "<img src=x onerror=alert(1)>https://evil.example/x",
        via: "client",
      },
    ];
    const { container } = render(
      <RedirectChainPanel findings={[brand(hostile)]} />,
    );
    expect(container.querySelector("a")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("hxxps://evil[.]example/x");
    expect(container.textContent).not.toContain("https://evil.example");
  });
});
