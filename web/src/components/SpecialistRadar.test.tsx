// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import type { Finding } from "@/lib/types";
import { ThemeProvider } from "@/hooks/useTheme";
import { RADAR_DOMAIN } from "@/lib/specialistRadar";
import { RadarPlot, SpecialistRadar } from "./SpecialistRadar";

const usage = { input_tokens: 1, output_tokens: 1, model_id: "m" };
const findings: Finding[] = [
  {
    agent: "url_analyst",
    status: "ok",
    verdict: "phishing",
    confidence: 92,
    signals: [],
    artifacts: [],
    usage,
    latency_ms: 1,
    calls: [],
  },
  {
    agent: "brand_visual",
    status: "ok",
    verdict: "legitimate",
    confidence: 64,
    signals: [],
    artifacts: [],
    usage,
    latency_ms: 1,
    calls: [],
  },
];

function renderRadar(f: Finding[] = findings) {
  render(
    <ThemeProvider>
      <SpecialistRadar findings={f} />
    </ThemeProvider>,
  );
}

describe("SpecialistRadar", () => {
  it("titles the chart and always lists all three verdict series in palette order", () => {
    renderRadar();
    expect(screen.getByText("Specialist confidence by verdict")).toBeTruthy();
    const legend = screen.getByRole("list", { name: "Radar legend" });
    const items = Array.from(legend.querySelectorAll("li"));
    expect(items.map((li) => li.dataset.verdict)).toEqual([
      "phishing",
      "suspicious",
      "legitimate",
    ]);
    // No specialist called it suspicious: still drawn, marked as empty.
    expect(items.map((li) => li.dataset.empty)).toEqual(["false", "true", "false"]);
    expect(items[1].textContent).toContain("Suspicious");
  });

  it("offers a table view with each specialist's verdict and confidence", () => {
    renderRadar();
    fireEvent.click(screen.getByRole("button", { name: "Table" }));
    const rows = screen.getAllByRole("row").map((r) => r.textContent);
    expect(rows).toContain("URL analystPhishing92%");
    expect(rows).toContain("Brand and visualLegitimate64%");
    expect(rows).toContain("Code analystNo report0%");
  });

  it("sizes the plot to the viewport so the chart fills its card", () => {
    renderRadar();
    const plot = screen.getByTestId("radar-plot");
    // jsdom has no layout, so the contract is the responsive height classes.
    expect(plot.className).toMatch(/\bh-64\b/);
    expect(plot.className).toMatch(/\bsm:h-80\b/);
    expect(plot.className).toMatch(/\blg:h-96\b/);
    expect(screen.getByTestId("radar-layout").className).toMatch(/\blg:grid-cols-2\b/);
  });

  it("reads out each specialist's verdict and confidence beside the chart", () => {
    renderRadar();
    const readout = screen.getByRole("list", { name: "Specialist readout" });
    const items = Array.from(readout.querySelectorAll("li"));
    expect(items.map((li) => li.dataset.agent)).toEqual([
      "url_analyst",
      "brand_visual",
      "code_analyst",
    ]);
    expect(items[0].textContent).toContain("URL analyst");
    expect(items[0].textContent).toContain("Phishing");
    expect(items[0].textContent).toContain("92%");
    expect(items[1].textContent).toContain("Legitimate");
    expect(items[2].textContent).toContain("No report");
    const bar = items[0].querySelector<HTMLElement>("[data-bar]");
    expect(bar?.style.width).toBe("92%");
  });

  it("says so instead of drawing an empty radar", () => {
    renderRadar([]);
    expect(screen.getByText(/No specialist reached a verdict/)).toBeTruthy();
  });

  it("draws every series on the grid's centre and radius, with the same 0 to 100 domain", () => {
    expect(RADAR_DOMAIN).toEqual([0, 100]);
    const data = (["url_analyst", "brand_visual", "code_analyst"] as const).map(
      (agent) => ({
        agent,
        note: null,
        specialist: agent,
        phishing: 100,
        suspicious: 50,
        legitimate: 0,
      }),
    );
    // Fixed size stands in for ResponsiveContainer, which jsdom cannot measure.
    const { container } = render(
      <ThemeProvider>
        <RadarPlot data={data} width={400} height={400} />
      </ThemeProvider>,
    );
    const vertices = (d: string | null) =>
      (d ?? "")
        .replace(/[MLZ]/g, " ")
        .trim()
        .split(/\s+/)
        .map((p) => p.split(",").map(Number))
        .slice(0, 3);
    const rings = Array.from(
      container.querySelectorAll(".recharts-polar-grid-concentric-polygon"),
    ).map((el) => vertices(el.getAttribute("d")));
    const outer = rings[rings.length - 1];
    const centre = rings[0][0];
    const radar = (name: string) =>
      vertices(
        container
          .querySelector(`.recharts-radar-polygon path[name="${name}"]`)
          ?.getAttribute("d") ?? null,
      );
    const close = (a: number[][], b: number[][]) =>
      a.forEach((pt, i) =>
        pt.forEach((c, j) => expect(c).toBeCloseTo(b[i][j], 3)),
      );
    // 100% sits on the outer ring, 50% halfway out from the shared centre.
    close(radar("Phishing"), outer);
    close(
      radar("Suspicious"),
      outer.map(([x, y]) => [
        centre[0] + (x - centre[0]) / 2,
        centre[1] + (y - centre[1]) / 2,
      ]),
    );
  });

  it("keeps the comma against the verdict in the readout ('Phishing, 92%')", () => {
    renderRadar();
    const readout = screen.getByRole("list", { name: "Specialist readout" });
    const item = readout.querySelector<HTMLElement>('[data-agent="url_analyst"]');
    const verdict = item?.querySelector<HTMLElement>("[data-verdict-text]");
    expect(verdict?.textContent).toBe("Phishing, 92%");
    // A flex gap between the label and ", 92%" rendered as "Phishing , 92%":
    // the label and the confidence must be one flex item.
    const flexParent = verdict?.parentElement;
    expect(flexParent?.className).toMatch(/\bgap-/);
    expect(
      Array.from(flexParent?.childNodes ?? []).filter(
        (n) => n.nodeType === Node.TEXT_NODE && n.textContent?.trim(),
      ),
    ).toEqual([]);
  });
});
