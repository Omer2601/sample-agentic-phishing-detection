// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { normalizeUrl, validateUrl } from "./utils";

/** The UI accepts up to 200 URLs per batch; the API accepts 1,000 (spec 2.4). */
export const UI_BATCH_MAX = 200;
/** Above this, the list goes to S3 as a CSV instead of a JSON body. */
export const JSON_BATCH_MAX = 50;

export interface ParsedUrlList {
  urls: string[];
  invalid: number;
  duplicates: number;
}

/** First CSV field of a line, honouring RFC 4180 quoting ("" is a literal quote). */
function firstField(line: string): string {
  const trimmed = line.trim();
  if (!trimmed.startsWith('"')) return trimmed.split(",")[0].trim();
  let out = "";
  for (let i = 1; i < trimmed.length; i += 1) {
    const ch = trimmed[i];
    if (ch === '"') {
      if (trimmed[i + 1] === '"') {
        out += '"';
        i += 1;
      } else {
        return out.trim();
      }
    } else {
      out += ch;
    }
  }
  return out.trim();
}

/**
 * Parse pasted text or a CSV file into unique, valid URLs. Mirrors the backend
 * rules (header optional, CRLF or LF, first column, blanks and duplicates dropped)
 * so the count shown before upload matches what the server will scan.
 */
export function parseUrlList(text: string): ParsedUrlList {
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/);
  const seen = new Set<string>();
  const urls: string[] = [];
  let invalid = 0;
  let duplicates = 0;
  lines.forEach((line, index) => {
    const value = firstField(line);
    if (!value) return;
    if (index === 0 && value.toLowerCase() === "url") return;
    const url = normalizeUrl(value);
    if (validateUrl(url) !== null) {
      invalid += 1;
      return;
    }
    if (seen.has(url)) {
      duplicates += 1;
      return;
    }
    seen.add(url);
    urls.push(url);
  });
  return { urls, invalid, duplicates };
}

export function toCsv(urls: string[]): string {
  const cell = (u: string) =>
    /[",\r\n]/.test(u) ? `"${u.replace(/"/g, '""')}"` : u;
  return ["url", ...urls.map(cell)].join("\n") + "\n";
}
