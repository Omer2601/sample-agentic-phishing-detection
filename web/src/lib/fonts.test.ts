// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

/*
 * The web tier's CSP allows fonts and styles from 'self' only (web/server/wsgi.py
 * _CSP), which is right: a third-party font request leaks every page view. The
 * Google Fonts @import was blocked on every page (UI e2e run 2, D6), so the app
 * uses the platform's own fonts and must never ask another origin for one.
 */
const root = path.resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(path.join(root, rel), "utf8");

/** The entries of one --font-* stack in the @theme block of src/index.css. */
function stack(name: "sans" | "mono"): string[] {
  const m = new RegExp(`--font-${name}:([^;]*);`).exec(read("src/index.css"));
  if (!m) throw new Error(`--font-${name} not found in src/index.css`);
  return m[1].split(",").map((entry) => entry.trim().replace(/^"|"$/g, ""));
}

describe("fonts stay first-party", () => {
  it("index.css and index.html load nothing from another origin", () => {
    for (const file of ["src/index.css", "index.html"]) {
      const text = read(file);
      expect(text, file).not.toMatch(/@import\s+url\(\s*["']?https?:/i);
      expect(text, file).not.toMatch(/url\(\s*["']?https?:/i);
      expect(text, file).not.toMatch(/fonts\.(googleapis|gstatic)\.com/i);
    }
  });

  it("font stacks name only system fonts, since no web font is shipped", () => {
    const sans = stack("sans");
    const mono = stack("mono");
    for (const stack of [sans, mono]) {
      expect(stack).not.toContain("Inter");
      expect(stack).not.toContain("JetBrains Mono");
      expect(stack.at(-1)).toMatch(/^(sans-serif|monospace)$/);
    }
    expect(sans[0]).toBe("ui-sans-serif");
    expect(mono[0]).toBe("ui-monospace");
  });
});
