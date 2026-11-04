// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { ModelUsage } from "@/lib/types";
import { modelLabel } from "@/lib/insights";
import { formatCost, formatTokens } from "@/lib/utils";
import { Card, CardBody } from "@/components/ui";

/** Tokens and cost are different scales, so they are columns here, never two y-axes. */
export function ModelUsageTable({ models }: { models: ModelUsage[] }) {
  const maxCost = Math.max(
    0.0001,
    ...models.map((m) => Number.parseFloat(m.cost_usd) || 0),
  );
  return (
    <Card>
      <CardBody className="space-y-3">
        <h3 className="text-sm font-semibold text-fg">Model usage</h3>
        {models.length === 0 && (
          <p className="text-xs text-muted">No model calls in this range.</p>
        )}
        {/* A list, not a three-column table: the model name, its cost bar and
            its tokens stack cleanly at any width. */}
        <ul className="divide-y divide-border/60">
          {models.map((m) => {
            const cost = Number.parseFloat(m.cost_usd) || 0;
            return (
              <li key={m.model_id} className="space-y-1.5 py-3 first:pt-0 last:pb-0">
                <div className="flex items-baseline justify-between gap-3 text-sm">
                  <span className="text-fg">{modelLabel(m.model_id)}</span>
                  <span className="font-semibold tabular-nums text-fg">
                    {m.cost_known === false ? "Cost unknown" : formatCost(m.cost_usd)}
                  </span>
                </div>
                <span className="block h-1.5 rounded-full bg-surface-2" aria-hidden>
                  <span
                    className="block h-full rounded-full bg-accent"
                    style={{ width: `${(cost / maxCost) * 100}%` }}
                  />
                </span>
                <p className="text-xs tabular-nums text-fg-subtle">
                  {formatTokens(m.input_tokens)} in,{" "}
                  {formatTokens(m.output_tokens)} out
                </p>
              </li>
            );
          })}
        </ul>
      </CardBody>
    </Card>
  );
}
