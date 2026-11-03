// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/hooks/useTheme";

const getScanReport = vi.fn();
const startDownload = vi.fn();
vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  api: { getScanReport: (...a: unknown[]) => getScanReport(...a) },
}));
vi.mock("@/lib/download", () => ({
  startDownload: (...a: unknown[]) => startDownload(...a),
}));
import type { ScanDetail } from "@/lib/types";
import { ResultView } from "./ResultView";

const record: ScanDetail = {
  scan_id: "9d9baee7-aaaa",
  url: "https://g00gle-mobile-verif.example/",
  batch_id: null,
  status: "COMPLETE",
  queued_at: "2026-09-29T12:00:00Z",
  started_at: "2026-09-29T12:00:01Z",
  completed_at: "2026-09-29T12:00:35Z",
  queue_wait_ms: 1000,
  total_ms: 34_000,
  verdict: {
    verdict: "phishing",
    risk_score: 95,
    confidence: "high",
    action: "block",
    summary: "Credential form posts off-domain.",
    disagreements: [],
    missed_by_specialists: [],
    report_markdown: "## Verdict\nPhishing",
  },
  findings: [
    {
      agent: "url_analyst",
      status: "ok",
      verdict: "phishing",
      confidence: 88,
      signals: [
        { name: "Lookalike domain", severity: "high", evidence: "g00gle" },
      ],
      artifacts: [],
      usage: { input_tokens: 1, output_tokens: 1, model_id: "m" },
      latency_ms: 2000,
      calls: [],
    },
  ],
  calls: [],
  cost_usd: "0.1432",
  error: null,
  attempts: 0,
  guardrail_events: [],
  artifacts: { screenshot: null },
};

function renderView() {
  render(
    <ThemeProvider>
      <MemoryRouter>
        <ResultView record={record} />
      </MemoryRouter>
    </ThemeProvider>,
  );
}

describe("ResultView", () => {
  it("shows verdict, time, cost and the report", () => {
    renderView();
    expect(screen.getByText("PHISHING")).toBeTruthy();
    expect(screen.getByText(/34s/)).toBeTruthy();
    expect(screen.getByText(/\$0\.1432/)).toBeTruthy();
    expect(screen.getByText(/Credential form posts off-domain/)).toBeTruthy();
  });

  it("shows the bold AI disclaimer badge on the verdict hero and the radar", () => {
    renderView();
    const badges = screen.getAllByTestId("disclaimer-badge");
    // Hero plus the specialist radar card.
    expect(badges.length).toBeGreaterThanOrEqual(2);
    for (const b of badges) {
      expect(b.getAttribute("role")).toBe("note");
      expect(b.textContent).toContain("AI OUTPUT: HUMAN REVIEW REQUIRED");
    }
  });

  it("renders no banner in the report panel (the AppShell shows the single one)", () => {
    renderView();
    expect(screen.queryByTestId("disclaimer-banner")).toBeNull();
  });

  it("labels a 404 verdict Error 404 rather than Unknown", () => {
    render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView
            record={{ ...record, verdict: { ...record.verdict!, verdict: "error_404" } }}
          />
        </MemoryRouter>
      </ThemeProvider>,
    );
    expect(screen.getByText("ERROR 404")).toBeTruthy();
    expect(screen.queryByText("UNKNOWN")).toBeNull();
  });

  it("labels a dead target Site down", () => {
    render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView
            record={{ ...record, verdict: { ...record.verdict!, verdict: "site_down" } }}
          />
        </MemoryRouter>
      </ThemeProvider>,
    );
    expect(screen.getByText("SITE DOWN")).toBeTruthy();
  });

  it("shows what the page's code does only when code_analyst sent insights", () => {
    renderView();
    expect(screen.queryByText("What the page's code does")).toBeNull();
    const withInsights: ScanDetail = {
      ...record,
      findings: [
        ...record.findings,
        {
          ...record.findings[0],
          agent: "code_analyst",
          insights: { script_count: 2, script_kb: 10 },
        },
      ],
    };
    render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView record={withInsights} />
        </MemoryRouter>
      </ThemeProvider>,
    );
    expect(screen.getByText("What the page's code does")).toBeTruthy();
  });

  it("shows the specialist radar and a section per specialist with its signals", () => {
    renderView();
    expect(screen.getByText("Specialist confidence by verdict")).toBeTruthy();
    const url = screen.getByRole("region", { name: "URL analyst" });
    expect(url.textContent).toContain("88% confident");
    expect(url.textContent).toContain("Lookalike domain");
  });

  it("downloads the HTML report for this scan", async () => {
    getScanReport.mockResolvedValue({ url: "https://s3.example/r", expires_in: 900 });
    renderView();
    fireEvent.click(screen.getByRole("button", { name: "Download report" }));
    await waitFor(() => expect(startDownload).toHaveBeenCalledWith("https://s3.example/r"));
    expect(getScanReport).toHaveBeenCalledWith("9d9baee7-aaaa");
  });

  it("shows the judge report open, before the specialist detail", () => {
    const withReport: ScanDetail = {
      ...record,
      verdict: {
        ...record.verdict!,
        report_markdown:
          "## Verdict\nPhishing\n## Reasoning\nWeighed all three.\n## Recommended actions\n### For the recipient\n- Do not sign in.",
      },
    };
    render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView record={withReport} />
        </MemoryRouter>
      </ThemeProvider>,
    );
    const reasoning = screen.getByRole("heading", { name: "Reasoning" });
    expect(reasoning.closest("details")?.open).toBe(true);
    const specialists = screen.getByRole("heading", { name: "Specialists" });
    expect(
      reasoning.compareDocumentPosition(specialists) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("shows similar past scans only when the scan has them", () => {
    const { unmount } = render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView record={record} />
        </MemoryRouter>
      </ThemeProvider>,
    );
    expect(screen.queryByText(/Similar past scans/)).toBeNull();
    unmount();
    render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView
            record={{
              ...record,
              similar_scans: [
                { scan_id: "a-old", summary: "hxxps://a[.]example/ | verdict=phishing" },
              ],
            }}
          />
        </MemoryRouter>
      </ThemeProvider>,
    );
    expect(screen.getAllByText(/Similar past scans/).length).toBeGreaterThan(0);
  });

  it.each(["", "0", "0.0000"])(
    "renders no stray dollar zero when the scan has no cost value (%j)",
    (cost) => {
      const { container } = render(
        <ThemeProvider>
          <MemoryRouter>
            <ResultView
              record={{
                ...record,
                cost_usd: cost,
                similar_scans: [],
                findings: [
                  {
                    ...record.findings[0],
                    agent: "brand_visual",
                    latency_ms: 0,
                    signals: [],
                  },
                ],
              }}
            />
          </MemoryRouter>
        </ThemeProvider>,
      );
      expect(container.textContent).not.toMatch(/\$0/);
      expect(screen.queryByText(/in tokens/)).toBeNull();
      const capture = screen.getByRole("region", { name: "Visual capture" });
      expect(capture.textContent).not.toMatch(/\$|(^|\D)0(\D|$)/);
    },
  );

  it("says the token cost is unknown when a model has no price", () => {
    render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView
            record={{
              ...record,
              cost_usd: "0.0615",
              unpriced_models: ["xx.anthropic.claude-future-9"],
            }}
          />
        </MemoryRouter>
      </ThemeProvider>,
    );
    expect(screen.getByText(/Token cost unknown/).textContent).toContain(
      "xx.anthropic.claude-future-9",
    );
    expect(screen.queryByText(/\$0\.0615 in tokens/)).toBeNull();
  });

  describe("verdict-first (report PENDING)", () => {
    const pending: ScanDetail = {
      ...record,
      report_status: "PENDING",
      report_started_at: "2026-09-29T12:00:35Z",
      verdict: { ...record.verdict!, report_markdown: "" },
    };
    const renderPending = () =>
      render(
        <ThemeProvider>
          <MemoryRouter>
            <ResultView record={pending} />
          </MemoryRouter>
        </ThemeProvider>,
      );

    it("shows the hero, gauge, radar and findings while the report is writing", () => {
      renderPending();
      expect(screen.getByText("PHISHING")).toBeTruthy();
      expect(screen.getByText(/Credential form posts off-domain/)).toBeTruthy();
      expect(screen.getByRole("heading", { name: "Specialists" })).toBeTruthy();
      expect(screen.getByText("Writing the full report")).toBeTruthy();
      expect(screen.getByRole("status").getAttribute("aria-busy")).toBe("true");
    });

    it("disables Download report, Copy and Download .md with a reason", () => {
      getScanReport.mockClear();
      renderPending();
      for (const name of [/^Download report/, /^Copy/, /^Download \.md/]) {
        expect((screen.getByRole("button", { name }) as HTMLButtonElement).disabled).toBe(true);
      }
      fireEvent.click(screen.getByRole("button", { name: /^Download report/ }));
      expect(getScanReport).not.toHaveBeenCalled();
    });

    it("shows the failure message with the verdict still visible", () => {
      render(
        <ThemeProvider>
          <MemoryRouter>
            <ResultView
              record={{ ...pending, report_status: "FAILED", report_error: "Model throttled" }}
            />
          </MemoryRouter>
        </ThemeProvider>,
      );
      expect(screen.getByText("PHISHING")).toBeTruthy();
      expect(
        screen.getByText(/The full report could not be generated\. The verdict above is still valid\./),
      ).toBeTruthy();
      expect(screen.getByText(/Model throttled/)).toBeTruthy();
    });

    it("treats a record without report_status as READY (legacy)", () => {
      renderView();
      expect(screen.queryByRole("status")).toBeNull();
      expect(
        (screen.getByRole("button", { name: /^Download report/ }) as HTMLButtonElement).disabled,
      ).toBe(false);
    });
  });
});

describe("ResultView capture state", () => {
  it("shows the page-not-observed note and the redirect chain", () => {
    const unseen: ScanDetail = {
      ...record,
      verdict: { ...record.verdict!, verdict: "suspicious", page_observed: false },
      findings: [
        {
          ...record.findings[0],
          redirect_chain: [
            { url: "https://bit.ly/x", via: "start", status: 301 },
            { url: "https://kit.pages.dev/", via: "http", cross_domain: true },
          ],
        },
      ],
    };
    render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView record={unseen} />
        </MemoryRouter>
      </ThemeProvider>,
    );
    expect(screen.getByRole("note", { name: "Page not observed" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Redirect chain" })).toBeTruthy();
    expect(screen.getByText("hxxps://kit[.]pages[.]dev/")).toBeTruthy();
  });

  it("shows neither for a record stored before these fields existed", () => {
    renderView();
    expect(screen.queryByRole("note", { name: "Page not observed" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Redirect chain" })).toBeNull();
  });

  it("renders a raw-HTML-only finding with no screenshot", () => {
    const rawOnly: ScanDetail = {
      ...record,
      verdict: { ...record.verdict!, verdict: "suspicious", page_observed: false },
      artifacts: { screenshot: null },
      findings: [
        {
          ...record.findings[0],
          agent: "brand_visual",
          page_observed: false,
          capture_note: "The page did not finish loading in the browser.",
          signals: [],
        },
        {
          ...record.findings[0],
          agent: "code_analyst",
          page_observed: false,
          capture_note: "Raw HTML was read instead of the rendered page.",
          signals: [
            {
              name: "static_html_only",
              severity: "low",
              evidence: "Login form posts off-domain.",
            },
          ],
        },
      ],
    };
    render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView record={rawOnly} />
        </MemoryRouter>
      </ThemeProvider>,
    );
    const note = screen.getByRole("note", { name: "Page not observed" });
    expect(note.textContent).toContain("only its raw HTML was read");
    expect(screen.getByText("Only the raw HTML could be read")).toBeTruthy();
    expect(screen.getByText(/its raw HTML was read with a plain request instead/)).toBeTruthy();
    expect(screen.getByText("Raw HTML was read instead of the rendered page.")).toBeTruthy();
    // The screenshot frame carries brand_visual's note; the code_analyst one is in its section.
    const visual = within(screen.getByRole("region", { name: "Visual capture" }));
    expect(visual.getByText("The page did not finish loading in the browser.")).toBeTruthy();
    expect(visual.getByText("Screenshot unavailable")).toBeTruthy();
    expect(visual.getByText("No screenshot was captured for this scan.")).toBeTruthy();
  });

  it("renders a www. sibling capture as not observed, with the catalog label", () => {
    const sibling: ScanDetail = {
      ...record,
      verdict: { ...record.verdict!, verdict: "suspicious", page_observed: false },
      findings: [
        {
          ...record.findings[0],
          agent: "brand_visual",
          page_observed: false,
          capture_note:
            "The certificate does not cover the www. name, so the same site without www. was captured instead. Visitors to this link see a certificate warning.",
          signals: [
            { name: "tls_error", severity: "low", evidence: "Certificate name error." },
            {
              name: "www_sibling_capture",
              severity: "low",
              evidence: "The bare host was captured instead.",
            },
          ],
        },
      ],
    };
    render(
      <ThemeProvider>
        <MemoryRouter>
          <ResultView record={sibling} />
        </MemoryRouter>
      </ThemeProvider>,
    );
    const note = screen.getByRole("note", { name: "Page not observed" });
    expect(note.textContent).toContain("the same site without www. was captured instead");
    expect(note.textContent).toContain("held at Suspicious at most");
    expect(screen.getByText("The same site without www. was captured instead")).toBeTruthy();
    expect(
      screen.getByText(/That page is evidence about the same site operator/),
    ).toBeTruthy();
    const visual = within(screen.getByRole("region", { name: "Visual capture" }));
    expect(visual.getByText(/Visitors to this link see a certificate warning\.$/)).toBeTruthy();
  });
});
