// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * A deliberately tiny Markdown subset for the orchestrator report: headings,
 * paragraphs, bullet and numbered lists, `---` rules, `>` quotes (shown as
 * paragraphs), `code` and **bold**. The report quotes
 * hostile page content, so this returns plain data that React renders as text
 * nodes. There is no link, image or HTML support, by design: anything else stays
 * literal text.
 */

export type ReportBlock =
  | { kind: "heading"; level: 2 | 3; text: string }
  | { kind: "paragraph"; text: string }
  | { kind: "list"; ordered: boolean; items: string[] }
  | { kind: "rule" };

export type InlineSpan = { kind: "text" | "code" | "strong"; text: string };

const HEADING = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
const BULLET = /^\s*[-*+]\s+(.*)$/;
const NUMBERED = /^\s*\d+[.)]\s+(.*)$/;
// The disclaimer wrapper puts `---` around every report and the guardrail note is a `>`
// quote: without these two they showed up as literal "---" and "> ..." text.
const RULE = /^([-*_])(\s*\1){2,}$/;
const QUOTE = /^>\s?/;

export function parseReport(markdown: string): ReportBlock[] {
  const blocks: ReportBlock[] = [];
  let paragraph: string[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;

  const flush = () => {
    if (paragraph.length) {
      blocks.push({ kind: "paragraph", text: paragraph.join(" ") });
      paragraph = [];
    }
    if (list) {
      blocks.push({ kind: "list", ...list });
      list = null;
    }
  };

  for (const raw of markdown.split(/\r?\n/)) {
    const line = raw.trim().replace(QUOTE, "").trim();
    if (!line) {
      flush();
      continue;
    }
    if (RULE.test(line)) {
      flush();
      blocks.push({ kind: "rule" });
      continue;
    }
    const heading = HEADING.exec(line);
    if (heading) {
      flush();
      blocks.push({
        kind: "heading",
        level: heading[1].length >= 3 ? 3 : 2,
        text: heading[2],
      });
      continue;
    }
    const bullet = BULLET.exec(raw);
    const numbered = bullet ? null : NUMBERED.exec(raw);
    const item = bullet ?? numbered;
    if (item) {
      const ordered = numbered !== null;
      if (paragraph.length || (list && list.ordered !== ordered)) flush();
      list ??= { ordered, items: [] };
      list.items.push(item[1].trim());
      continue;
    }
    if (list) {
      // A wrapped line continues the last list item.
      const last = list.items.length - 1;
      list.items[last] = `${list.items[last]} ${line}`;
      continue;
    }
    paragraph.push(line);
  }
  flush();
  return blocks;
}

const INLINE = /`([^`]+)`|\*\*([^*]+)\*\*/g;

export function parseInline(text: string): InlineSpan[] {
  const spans: InlineSpan[] = [];
  let at = 0;
  for (const match of text.matchAll(INLINE)) {
    const start = match.index ?? 0;
    if (start > at) spans.push({ kind: "text", text: text.slice(at, start) });
    if (match[1] !== undefined) spans.push({ kind: "code", text: match[1] });
    else spans.push({ kind: "strong", text: match[2] });
    at = start + match[0].length;
  }
  if (at < text.length) spans.push({ kind: "text", text: text.slice(at) });
  return spans;
}
