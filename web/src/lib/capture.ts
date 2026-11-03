// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Finding, RedirectHop, Verdict } from "./types";

const BROWSER_AGENTS = new Set(["brand_visual", "code_analyst"]);
// The browser chain shows script and warning hops too, so it is preferred.
const CHAIN_ORDER = ["brand_visual", "code_analyst", "url_analyst"] as const;

/**
 * Whether the real page was seen: the verdict's own field, or (records without it) any
 * browser finding that says so. null when nothing says either way.
 */
export function pageObserved(
  verdict: Verdict | null | undefined,
  findings: Finding[],
): boolean | null {
  if (typeof verdict?.page_observed === "boolean") return verdict.page_observed;
  const seen = findings
    .filter((f) => BROWSER_AGENTS.has(f.agent))
    .map((f) => f.page_observed)
    .filter((v): v is boolean => typeof v === "boolean");
  return seen.length ? seen.some(Boolean) : null;
}

/** The fullest redirect chain (two hops or more) and the specialist that measured it. */
export function redirectChain(
  findings: Finding[],
): { agent: Finding["agent"]; hops: RedirectHop[] } | null {
  for (const agent of CHAIN_ORDER) {
    const hops = findings.find((f) => f.agent === agent)?.redirect_chain ?? [];
    if (hops.length >= 2) return { agent, hops };
  }
  return null;
}

export const HOP_VIA_LABEL: Record<string, string> = {
  start: "Submitted URL",
  http: "HTTP redirect",
  client: "Script or meta refresh",
  warning_bypass: "Proceeded past the warning",
};
