// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { JSON_BATCH_MAX, UI_BATCH_MAX, parseUrlList, toCsv } from "./urlList";

const ROWS = [
  "http://wallet-login.example.com/",
  "https://shop.example.net/fonts/purchase.html?e=user@example.net",
  "http://pay-verify.example.org/",
];

describe("parseUrlList", () => {
  it("skips a url header", () => {
    expect(parseUrlList(["url", ...ROWS].join("\n")).urls).toEqual(ROWS);
  });

  it("accepts a file with no header", () => {
    expect(parseUrlList(ROWS.join("\n")).urls).toEqual(ROWS);
  });

  it("accepts CRLF line endings and a UTF-8 BOM", () => {
    expect(parseUrlList("\uFEFFurl\r\n" + ROWS.join("\r\n") + "\r\n").urls).toEqual(
      ROWS,
    );
  });

  it("takes the first column and honours quoted commas", () => {
    const parsed = parseUrlList(
      'url,label\n"https://a.example/x,y",bad\nhttps://b.example,ok',
    );
    expect(parsed.urls).toEqual(["https://a.example/x,y", "https://b.example"]);
  });

  it("counts duplicates and invalid rows instead of sending them", () => {
    const parsed = parseUrlList(
      `${ROWS[0]}\n${ROWS[0]}\nnot a url\nftp://x.example\n\n`,
    );
    expect(parsed).toEqual({ urls: [ROWS[0]], invalid: 2, duplicates: 1 });
  });

  it("adds https to bare hosts, matching the single-scan form", () => {
    expect(parseUrlList("www.example.com").urls).toEqual([
      "https://www.example.com",
    ]);
  });
});

describe("toCsv", () => {
  it("writes a header and quotes values that need it", () => {
    expect(toCsv(["https://a.example", 'https://b.example/"q",x'])).toBe(
      'url\nhttps://a.example\n"https://b.example/""q"",x"\n',
    );
  });

  it("round-trips through the parser", () => {
    expect(parseUrlList(toCsv(ROWS)).urls).toEqual(ROWS);
  });
});

it("exposes the caps from the spec", () => {
  expect(UI_BATCH_MAX).toBe(200);
  expect(JSON_BATCH_MAX).toBe(50);
});
