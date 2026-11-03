// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { ReactNode } from "react";
import { Moon, ShieldHalf, Sun } from "lucide-react";
import { useTheme } from "@/hooks/useTheme";
import { CheckIcon } from "./icons";

/**
 * Two-panel shell for the screens a visitor sees before they have a session.
 *
 * Desktop puts the form on the left and a decorative panel on the right; below
 * the `lg` breakpoint the decorative panel is dropped entirely and the form
 * becomes a single centred column, because on a phone the artwork would push the
 * first input below the fold to no benefit.
 *
 * The brand mark reuses the icon the signed-in shell already imports, so this
 * screen adds no new icon weight to the bundle while still looking like the same
 * product.
 */

/** Copy on the decorative panel. Kept vague about counts so it cannot go stale. */
const HIGHLIGHTS = [
  "Suspect pages rendered in an isolated browser",
  "Three specialist agents, one orchestrated verdict",
  "Evidence and a screenshot behind every verdict",
];

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button
      type="button"
      onClick={toggle}
      className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-border bg-surface text-fg-subtle transition-colors hover:text-fg"
      aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
    >
      {theme === "dark" ? <Sun className="h-4.5 w-4.5" /> : <Moon className="h-4.5 w-4.5" />}
    </button>
  );
}

function BrandMark() {
  return (
    <div className="flex items-center gap-2.5">
      <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-linear-to-br/srgb from-accent to-accent-2 text-white shadow-glow">
        <ShieldHalf className="h-5 w-5" aria-hidden="true" />
      </span>
      <div className="min-w-0 leading-tight">
        <p className="text-sm font-extrabold tracking-tight text-fg">Multi-Agent Phishing URL Detection</p>
        <p className="text-[10px] font-medium uppercase tracking-widest text-muted">
          Analyst Console
        </p>
      </div>
    </div>
  );
}

/**
 * Decorative artwork, hand-rolled SVG.
 *
 * A shield with a tick inside a dotted orbit: it reads as "checked and cleared"
 * at a glance and costs a few hundred bytes, where an illustration asset would
 * cost a network request and a design dependency. Purely decorative, so it is
 * hidden from assistive technology.
 */
function ShieldArt() {
  return (
    <svg viewBox="0 0 240 240" className="h-64 w-64" aria-hidden="true">
      <circle
        cx="120"
        cy="120"
        r="108"
        fill="none"
        stroke="rgb(255 255 255 / 0.16)"
        strokeWidth="1"
      />
      <circle
        cx="120"
        cy="120"
        r="86"
        fill="none"
        stroke="rgb(255 255 255 / 0.22)"
        strokeWidth="1"
        strokeDasharray="3 7"
      />
      <path
        d="M120 46 186 71v50c0 39-27 65-66 76-39-11-66-37-66-76V71z"
        fill="rgb(255 255 255 / 0.14)"
        stroke="rgb(255 255 255 / 0.6)"
        strokeWidth="2"
      />
      <path
        d="M96 121 112 137 148 99"
        fill="none"
        stroke="rgb(255 255 255 / 0.95)"
        strokeWidth="7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="120" cy="12" r="4" fill="rgb(255 255 255 / 0.85)" />
      <circle cx="228" cy="120" r="3" fill="rgb(255 255 255 / 0.7)" />
      <circle cx="34" cy="86" r="2.5" fill="rgb(255 255 255 / 0.6)" />
      <circle cx="66" cy="204" r="3" fill="rgb(255 255 255 / 0.55)" />
    </svg>
  );
}

function ArtPanel() {
  return (
    <div className="relative hidden overflow-hidden bg-linear-to-br/srgb from-accent via-accent to-accent-2 lg:block">
      {/*
       * A dark scrim over the token-driven gradient. The accent tokens shift
       * between themes (indigo-500 in light, indigo-400 in dark) and white text
       * on the lighter of the two would sit under 4.5:1, so the scrim fixes the
       * contrast of this panel at roughly 10:1 in both themes while the hue
       * still follows the theme.
       */}
      <div className="absolute inset-0 bg-slate-950/55" aria-hidden="true" />
      <div
        className="absolute -left-24 top-16 h-72 w-72 rounded-full bg-white/10 blur-3xl"
        aria-hidden="true"
      />
      <div
        className="absolute -bottom-24 right-0 h-80 w-80 rounded-full bg-accent-2/30 blur-3xl"
        aria-hidden="true"
      />

      <div className="relative flex h-full flex-col justify-center gap-10 px-14 py-16 text-white xl:px-20">
        <ShieldArt />
        <div className="max-w-sm">
          <p className="text-3xl font-extrabold leading-tight tracking-tight">
            Phishing verdicts you can defend.
          </p>
          <p className="mt-3 text-sm leading-relaxed text-white/85">
            Every link is opened in a sandbox, checked by three specialist agents, and
            ruled on with the evidence attached.
          </p>
          <ul className="mt-8 space-y-3">
            {HIGHLIGHTS.map((point) => (
              <li key={point} className="flex items-start gap-2.5 text-sm text-white/90">
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-white/15">
                  <CheckIcon className="h-3 w-3" />
                </span>
                {point}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-full lg:grid lg:grid-cols-2">
      <div className="flex min-h-full flex-col px-6 py-8 sm:px-10 lg:px-14">
        <div className="flex items-center justify-between gap-4">
          <BrandMark />
          <ThemeToggle />
        </div>

        <main className="flex flex-1 items-center justify-center py-12">
          <div className="w-full max-w-md">{children}</div>
        </main>

        <p className="text-center text-[11px] leading-relaxed text-muted">
          Sample code for an AWS blog post. Suspect URLs are analysed in an isolated
          environment, never on your machine.
        </p>
      </div>

      <ArtPanel />
    </div>
  );
}
