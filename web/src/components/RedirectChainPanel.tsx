// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useId } from "react";
import { Route } from "lucide-react";
import type { Finding } from "@/lib/types";
import { HOP_VIA_LABEL, redirectChain } from "@/lib/capture";
import { defang } from "@/lib/signals";
import { specialistVisual } from "./specialistVisual";
import { Badge, Card, CardBody } from "./ui";

/**
 * How the scan got from the submitted URL to the page that was judged. Every URL comes from
 * the scanned site, so it is rendered defanged as plain text, never as a link.
 */
export function RedirectChainPanel({ findings }: { findings: Finding[] }) {
  const headingId = useId();
  const chain = redirectChain(findings);
  if (!chain) return null;
  return (
    <section aria-labelledby={headingId}>
      <Card>
        <CardBody className="space-y-4">
          <div className="flex items-center gap-3">
            <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent/15 text-accent">
              <Route className="h-4 w-4" aria-hidden />
            </span>
            <div className="min-w-0">
              <h4 id={headingId} className="text-base font-semibold text-fg">
                Redirect chain
              </h4>
              <p className="text-xs text-muted">
                {chain.hops.length} hops, measured by{" "}
                {specialistVisual(chain.agent).label}
              </p>
            </div>
          </div>
          <ol className="space-y-2">
            {chain.hops.map((hop, i) => (
              <li
                key={`${hop.url}-${i}`}
                className="space-y-1 rounded-xl border border-border px-3 py-2 text-sm"
              >
                <div className="flex flex-wrap items-center gap-2 text-xs text-fg-subtle">
                  <span className="font-medium text-fg">
                    {i + 1}. {HOP_VIA_LABEL[hop.via ?? "start"] ?? hop.via}
                  </span>
                  {hop.status != null && <span>HTTP {hop.status}</span>}
                  {hop.cross_domain && <Badge tone="warn">New site</Badge>}
                  {hop.free_hosting && <Badge tone="warn">Free hosting</Badge>}
                  {hop.shortener && <Badge tone="warn">Shortener</Badge>}
                  {hop.error && <Badge tone="danger">Did not load</Badge>}
                </div>
                <p className="font-mono text-xs break-all text-fg">
                  {defang(hop.url)}
                </p>
                {hop.error && (
                  <p className="font-mono text-xs text-muted">{hop.error}</p>
                )}
              </li>
            ))}
          </ol>
        </CardBody>
      </Card>
    </section>
  );
}
