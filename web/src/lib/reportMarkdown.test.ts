// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { parseInline, parseReport } from "./reportMarkdown";

const REPORT = [
  "## Verdict",
  "Phishing, risk 95, block.",
  "## Reasoning",
  "First line of a paragraph",
  "continues here.",
  "",
  "Second paragraph.",
  "## Evidence",
  "- url_analyst: typosquat.",
  "* brand_visual: Google sign-in.",
  "## Recommended actions",
  "### For the recipient",
  "1. Do not sign in.",
  "2. Report the message.",
  "### For the security team",
  "- Block `g00gle[.]com`.",
  "## Gaps",
  "None.",
].join("\n");

describe("parseReport", () => {
  it("splits headings, paragraphs and lists in order", () => {
    expect(parseReport(REPORT)).toEqual([
      { kind: "heading", level: 2, text: "Verdict" },
      { kind: "paragraph", text: "Phishing, risk 95, block." },
      { kind: "heading", level: 2, text: "Reasoning" },
      { kind: "paragraph", text: "First line of a paragraph continues here." },
      { kind: "paragraph", text: "Second paragraph." },
      { kind: "heading", level: 2, text: "Evidence" },
      {
        kind: "list",
        ordered: false,
        items: ["url_analyst: typosquat.", "brand_visual: Google sign-in."],
      },
      { kind: "heading", level: 2, text: "Recommended actions" },
      { kind: "heading", level: 3, text: "For the recipient" },
      {
        kind: "list",
        ordered: true,
        items: ["Do not sign in.", "Report the message."],
      },
      { kind: "heading", level: 3, text: "For the security team" },
      { kind: "list", ordered: false, items: ["Block `g00gle[.]com`."] },
      { kind: "heading", level: 2, text: "Gaps" },
      { kind: "paragraph", text: "None." },
    ]);
  });

  it("treats a level 1 heading as a level 2 heading", () => {
    expect(parseReport("# Report")).toEqual([
      { kind: "heading", level: 2, text: "Report" },
    ]);
  });

  it("handles CRLF and an empty report", () => {
    expect(parseReport("")).toEqual([]);
    expect(parseReport("## A\r\nb")).toEqual([
      { kind: "heading", level: 2, text: "A" },
      { kind: "paragraph", text: "b" },
    ]);
  });

  it("turns the disclaimer's --- into rules and drops the > of a quote", () => {
    const md = [
      "**AI-generated analysis: human review required.** Review it.",
      "",
      "---",
      "",
      "The analysis was withheld.",
      "",
      "> Parts of this report were withheld by the output guardrail.",
      "",
      "***",
    ].join("\n");
    expect(parseReport(md)).toEqual([
      {
        kind: "paragraph",
        text: "**AI-generated analysis: human review required.** Review it.",
      },
      { kind: "rule" },
      { kind: "paragraph", text: "The analysis was withheld." },
      {
        kind: "paragraph",
        text: "Parts of this report were withheld by the output guardrail.",
      },
      { kind: "rule" },
    ]);
  });

  it("keeps HTML and link syntax as plain text", () => {
    const blocks = parseReport("<script>x</script> [go](https://evil.example)");
    expect(blocks).toEqual([
      {
        kind: "paragraph",
        text: "<script>x</script> [go](https://evil.example)",
      },
    ]);
  });
});

describe("parseInline", () => {
  it("splits code and bold spans and leaves the rest as text", () => {
    expect(parseInline("Block `a[.]com` **now** please")).toEqual([
      { kind: "text", text: "Block " },
      { kind: "code", text: "a[.]com" },
      { kind: "text", text: " " },
      { kind: "strong", text: "now" },
      { kind: "text", text: " please" },
    ]);
  });

  it("leaves an unmatched marker as text", () => {
    expect(parseInline("a `b")).toEqual([{ kind: "text", text: "a `b" }]);
  });
});
