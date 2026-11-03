// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { EyeOff } from "lucide-react";
import type { Finding, Verdict } from "@/lib/types";
import { pageObserved } from "@/lib/capture";

const WARNINGS = new Set([
  "cloudflare_phishing_warning",
  "cloudflare_malware_warning",
]);

/**
 * Shown when no browser capture saw the site's real page. With a provider warning in front
 * of it, or only the www. sibling captured, the backend also holds the verdict at Suspicious
 * (risk 69 at most), and this says so.
 */
export function PageNotObservedNotice({
  verdict,
  findings,
}: {
  verdict: Verdict;
  findings: Finding[];
}) {
  if (pageObserved(verdict, findings) !== false) return null;
  const has = (match: (name: string) => boolean) =>
    findings.some((f) => f.signals.some((s) => match(s.name)));
  const warned = has((n) => WARNINGS.has(n));
  // code_analyst fell back to a plain GET of the HTML: some code was read, nothing rendered.
  const rawHtmlOnly = has((n) => n === "static_html_only");
  // The certificate did not cover www., so the bare host was captured; the backend holds it too.
  const wwwSibling = has((n) => n === "www_sibling_capture");
  return (
    <div
      role="note"
      aria-label="Page not observed"
      className="flex items-start gap-2 rounded-xl border border-warn/40 bg-warn/5 px-4 py-3 text-sm text-fg-subtle animate-fade-in"
    >
      <EyeOff className="mt-0.5 h-4 w-4 shrink-0 text-warn" aria-hidden />
      <p>
        <span className="font-semibold text-fg">Page not observed.</span>{" "}
        {warned
          ? "A provider warning stood in front of the site and the browser could not get past it, so the verdict is held at Suspicious at most."
          : wwwSibling
            ? "The certificate does not cover the www. name, so the same site without www. was captured instead. Visitors to this link see a certificate warning. The verdict is held at Suspicious at most."
            : rawHtmlOnly
              ? "The browser could not load the site's real page, so only its raw HTML was read (not rendered, scripts not run). The verdict rests on the URL and that HTML."
              : "The browser never saw the site's real page (a bot check, block page or failed capture stood in front of it), so the verdict rests on the URL and what was seen."}
      </p>
    </div>
  );
}
