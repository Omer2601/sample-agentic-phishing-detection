// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, ChevronDown, Loader2, RefreshCw, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";
import type { FeedGroup, FeedItem, FeedResponse, RiskTier } from "@/lib/types";
import { cn } from "@/lib/utils";
import { Button } from "./ui";

/**
 * Target picker with risk tiers.
 *
 * Three ways to start a scan without typing a URL: a grouped dropdown, a tab strip,
 * and one-click chips. All three are fed by the backend's /feed/phishing endpoint.
 *
 * High risk is a curated set of illustrative phishing examples (typosquats,
 * deceptive subdomains, IP-based URLs), safe to display and intentionally NOT live
 * malicious hosts. Medium risk is malware and unwanted-software test pages, and low
 * risk is well-known legitimate sites, which is what makes the false-positive rate
 * observable: a detector that only ever sees phishing tells you nothing about how
 * it treats a real bank.
 *
 * The dropdown renders as an inline panel that pushes content down rather than an
 * overlay. An overlay is the conventional choice, but here it sat on top of the
 * suggestion chips and the notice, which is precisely the content a user
 * needs while choosing a target to scan.
 */

/** Per-tier presentation. Colour carries the risk, so it is defined in one place. */
const TIER_STYLE: Record<RiskTier, { chip: string; dot: string; text: string; label: string }> = {
  high: {
    chip: "border-danger/40 text-danger hover:bg-danger/10",
    dot: "bg-danger",
    text: "text-danger",
    label: "Phishing",
  },
  medium: {
    chip: "border-warn/40 text-warn hover:bg-warn/10",
    dot: "bg-warn",
    text: "text-warn",
    label: "Medium risk",
  },
  low: {
    chip: "border-safe/40 text-safe hover:bg-safe/10",
    dot: "bg-safe",
    text: "text-safe",
    label: "Safe",
  },
};

const TIER_ORDER: RiskTier[] = ["high", "medium", "low"];

export function LiveTargetPicker({
  onPick,
  disabled,
}: {
  onPick: (url: string) => void;
  disabled?: boolean;
}) {
  const [feed, setFeed] = useState<FeedResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [tier, setTier] = useState<RiskTier>("high");

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      setFeed(await api.getSuggestions(15));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load the target feed");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const groups: FeedGroup[] = useMemo(
    () =>
      TIER_ORDER.map((t) => feed?.groups?.find((g) => g.risk === t)).filter(
        (g): g is FeedGroup => Boolean(g && g.items.length),
      ),
    [feed],
  );

  const active = groups.find((g) => g.risk === tier) ?? groups[0];
  const activeItems: FeedItem[] = active?.items ?? [];

  return (
    <div className="mt-5 border-t border-border/60 pt-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-accent" />
          <div>
            <p className="text-sm font-semibold text-fg">Pick a target to scan</p>
            <p className="text-[11px] text-muted">
              {loading
                ? "Loading targets…"
                : groups.length
                  ? `${groups.map((g) => `${g.items.length} ${TIER_STYLE[g.risk].label.toLowerCase()}`).join(" · ")}`
                  : "No targets available"}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="ghost"
            onClick={() => setOpen((o) => !o)}
            disabled={disabled || loading || groups.length === 0}
            className="gap-1.5 text-xs"
            aria-expanded={open}
          >
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {open ? "Hide list" : "Browse all targets"}
            <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-180")} />
          </Button>
          <Button
            type="button"
            variant="ghost"
            onClick={() => void load()}
            disabled={disabled || loading}
            aria-label="Refresh the target feed"
            className="px-2"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          </Button>
        </div>
      </div>

      {/* Tier tabs. Counts are shown so an empty tier is visibly empty rather than
          looking like a broken filter. */}
      {groups.length > 0 ? (
        <div
          role="tablist"
          aria-label="Risk category"
          className="mt-3 flex flex-wrap gap-1.5 rounded-lg border border-border bg-surface-2/40 p-1"
        >
          {groups.map((g) => {
            const s = TIER_STYLE[g.risk];
            const selected = active?.risk === g.risk;
            return (
              <button
                key={g.risk}
                role="tab"
                type="button"
                aria-selected={selected}
                onClick={() => setTier(g.risk)}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors",
                  selected ? "bg-surface text-fg shadow-xs" : "text-muted hover:text-fg",
                )}
              >
                <span className={cn("h-2 w-2 rounded-full", s.dot)} aria-hidden />
                {s.label}
                <span className="tabular-nums text-[10px] text-muted">{g.items.length}</span>
              </button>
            );
          })}
        </div>
      ) : null}

      {/* Quick chips for the selected tier. */}
      {activeItems.length > 0 ? (
        <>
          {active?.description ? (
            <p className="mt-3 text-[11px] text-muted">{active.description}</p>
          ) : null}
          <div className="mt-2 flex flex-wrap gap-2">
            {activeItems.slice(0, 6).map((item) => (
              <button
                key={item.url}
                type="button"
                disabled={disabled}
                onClick={() => onPick(item.url)}
                title={item.url}
                className={cn(
                  "max-w-full truncate rounded-full border bg-surface px-3 py-1 text-xs transition-colors",
                  TIER_STYLE[item.risk].chip,
                  "disabled:cursor-not-allowed disabled:opacity-50",
                )}
              >
                {item.risk === "high" ? item.host : item.label || item.host}
              </button>
            ))}
          </div>
        </>
      ) : null}

      {/* Full grouped list. Inline, so it never covers the chips or the warning. */}
      {open && groups.length > 0 ? (
        <div className="mt-3 max-h-80 overflow-y-auto rounded-lg border border-border bg-surface-2/40 p-2">
          {groups.map((g) => {
            const s = TIER_STYLE[g.risk];
            return (
              <div key={g.risk} className="mb-3 last:mb-0">
                <div className="mb-1.5 flex items-center gap-1.5 px-1">
                  <span className={cn("h-2 w-2 rounded-full", s.dot)} aria-hidden />
                  <span className={cn("text-[11px] font-semibold uppercase tracking-wide", s.text)}>
                    {s.label}
                  </span>
                  <span className="text-[11px] text-muted">· {g.description}</span>
                </div>
                <ul>
                  {g.items.map((item) => (
                    <li key={item.url}>
                      <button
                        type="button"
                        disabled={disabled}
                        onClick={() => {
                          setOpen(false);
                          onPick(item.url);
                        }}
                        className="w-full rounded-md px-2 py-1.5 text-left transition-colors hover:bg-surface disabled:opacity-50"
                      >
                        <span className="flex items-baseline justify-between gap-3">
                          <span className="truncate text-xs font-medium text-fg">
                            {item.label || item.host}
                          </span>
                          <span className={cn("shrink-0 text-[10px] font-semibold", s.text)}>
                            {s.label}
                          </span>
                        </span>
                        <span className="mt-0.5 block truncate font-mono text-[11px] text-muted">
                          {item.url}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      ) : null}

      {/* A third-party feed being unreachable is not the same as "no phishing
          exists", so say which happened. */}
      {!loading && groups.length === 0 ? (
        <p className="mt-3 text-xs text-muted">
          {error ?? feed?.message ?? "No targets available. Enter a URL above to scan."}
        </p>
      ) : null}

      {groups.some((g) => g.risk === "high") ? (
        <p className="mt-3 flex items-start gap-1.5 text-[11px] text-warn">
          <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
          <span>
            {feed?.warning ??
              "Phishing entries are illustrative examples for display, not live malicious URLs, and may not resolve when scanned. To test a live URL, paste it into the box above or use the scan APIs."}
          </span>
        </p>
      ) : null}
    </div>
  );
}
