// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState, type ReactNode } from "react";
import { Link, NavLink } from "react-router-dom";
import {
  ScanLine,
  Layers,
  History,
  BarChart3,
  Terminal,
  Moon,
  Sun,
  Menu,
  X,
  ShieldHalf,
  Loader2,
  LogOut,
} from "lucide-react";
import { useActiveBatches } from "@/hooks/useActiveBatches";
import { useTheme } from "@/hooks/useTheme";
import { batchCounts } from "@/lib/batch";
import { cn } from "@/lib/utils";
import { DisclaimerBanner } from "./DisclaimerBanner";

/**
 * Server route that clears the HttpOnly session cookie and ends the Cognito
 * session (web/server/auth.py logout_redirect). It must be a full-page
 * navigation: the SPA cannot clear an HttpOnly cookie itself, and a router
 * link would never reach the server.
 */
export const SIGN_OUT_PATH = "/auth/logout";

const NAV = [
  { to: "/", label: "Scan", icon: ScanLine, end: true },
  { to: "/batch", label: "Batch", icon: Layers, end: false },
  { to: "/history", label: "History", icon: History, end: false },
  { to: "/insights", label: "Insights", icon: BarChart3, end: false },
  { to: "/api-console", label: "API", icon: Terminal, end: false },
];

function NavItems({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="space-y-1">
      {NAV.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors",
              isActive
                ? "bg-accent/15 text-accent"
                : "text-fg-subtle hover:bg-surface-2 hover:text-fg",
            )
          }
        >
          <Icon className="h-4.5 w-4.5" />
          {label}
        </NavLink>
      ))}
    </nav>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-2.5">
      <span className="relative inline-flex h-9 w-9 items-center justify-center rounded-xl bg-linear-to-br/srgb from-accent to-accent-2 text-white shadow-glow">
        <ShieldHalf className="h-5 w-5" />
      </span>
      <div className="min-w-0 leading-tight">
        <p className="text-sm font-extrabold tracking-tight text-fg">Multi-Agent Phishing URL Detection</p>
        <p className="text-[10px] font-medium uppercase tracking-widest text-muted">Analyst Console</p>
      </div>
    </div>
  );
}

/**
 * Always-visible pointer to running batches, so leaving the Batch page mid-run
 * never hides progress. Reads the shared provider; it does no polling of its own.
 */
function ActiveBatchIndicator() {
  const { active } = useActiveBatches();
  if (active.length === 0) return null;
  const done = active.reduce((n, b) => n + batchCounts(b).done, 0);
  const total = active.reduce((n, b) => n + b.total, 0);
  const to =
    active.length === 1
      ? `/batch/${encodeURIComponent(active[0].batch_id)}`
      : "/batch";
  return (
    <Link
      to={to}
      className="inline-flex items-center gap-2 rounded-xl border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent transition-colors hover:bg-accent/15"
      aria-live="polite"
    >
      <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
      {active.length === 1
        ? "1 batch running"
        : `${active.length} batches running`}
      <span className="tabular-nums text-fg-subtle">
        {done}/{total}
      </span>
    </Link>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { theme, toggle } = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen lg:flex">
      {/* Sidebar (desktop). The column is a flex child, so its background and
          border stretch to the full page height; the nav inside is sticky so it
          stays in view. A fixed, viewport-high aside stopped at the first
          screen in full-page screenshots. */}
      <div className="hidden w-64 shrink-0 border-r border-border bg-surface/60 backdrop-blur-md lg:block">
        <aside className="sticky top-0 flex h-screen flex-col">
          <div className="p-5">
            <Brand />
          </div>
          <div className="flex-1 px-3">
            <NavItems />
          </div>
          <div className="p-4">
            <div className="rounded-xl border border-border bg-surface-2/50 p-3 text-[11px] leading-relaxed text-fg-subtle">
              <p className="font-semibold text-fg">Isolated analysis</p>
              <p className="mt-1">
                Suspect URLs open in an isolated AgentCore browser. Nothing runs on your machine.
              </p>
            </div>
          </div>
        </aside>
      </div>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/50" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 border-r border-border bg-surface p-5">
            <div className="mb-6 flex items-center justify-between">
              <Brand />
              <button
                onClick={() => setMobileOpen(false)}
                className="rounded-lg p-1.5 text-muted hover:bg-surface-2 hover:text-fg"
                aria-label="Close navigation"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <NavItems onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      {/* Main column */}
      <div className="min-w-0 lg:flex-1">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between gap-3 border-b border-border bg-bg/70 px-4 backdrop-blur-md sm:px-6">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(true)}
              className="rounded-lg p-2 text-muted hover:bg-surface-2 hover:text-fg lg:hidden"
              aria-label="Open navigation"
            >
              <Menu className="h-5 w-5" />
            </button>
            <ActiveBatchIndicator />
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={toggle}
              className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-border bg-surface text-fg-subtle transition-colors hover:text-fg"
              aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            >
              {theme === "dark" ? <Sun className="h-4.5 w-4.5" /> : <Moon className="h-4.5 w-4.5" />}
            </button>
            <a
              href={SIGN_OUT_PATH}
              className="inline-flex h-9 items-center gap-2 rounded-xl border border-border bg-surface px-3 text-sm font-medium text-fg-subtle transition-colors hover:text-fg"
            >
              <LogOut className="h-4 w-4" aria-hidden />
              <span>Sign out</span>
            </a>
          </div>
        </header>

        {/* Persistent on every page, right under the header. */}
        <div className="mx-auto max-w-6xl px-4 pt-4 sm:px-6">
          <DisclaimerBanner />
        </div>

        <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">{children}</main>
      </div>
    </div>
  );
}
