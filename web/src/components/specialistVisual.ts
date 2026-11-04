// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Code2, Fingerprint, Link2 } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { SpecialistName } from "@/lib/types";

/**
 * Identity marks for the three specialists. They always appear next to the
 * specialist's name, so colour is never the only cue. The verdict palette stays
 * reserved for verdicts.
 */
export const SPECIALIST_VISUAL: Record<
  SpecialistName,
  { label: string; role: string; icon: LucideIcon; color: string; soft: string }
> = {
  url_analyst: {
    label: "URL analyst",
    role: "Structure, lookalikes, TLD and WHOIS age",
    icon: Link2,
    color: "#818cf8",
    soft: "rgba(129,140,248,0.15)",
  },
  brand_visual: {
    label: "Brand and visual",
    role: "Rendered page, logo and impersonation",
    icon: Fingerprint,
    color: "#f472b6",
    soft: "rgba(244,114,182,0.15)",
  },
  code_analyst: {
    label: "Code analyst",
    role: "DOM, scripts, forms and exfiltration",
    icon: Code2,
    color: "#22d3ee",
    soft: "rgba(34,211,238,0.15)",
  },
};

export function specialistVisual(name: SpecialistName) {
  return SPECIALIST_VISUAL[name];
}
