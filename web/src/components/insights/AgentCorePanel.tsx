// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { AgentCoreStat } from "@/lib/types";
import { callLabel, callP95 } from "@/lib/insights";
import { formatMs } from "@/lib/utils";
import { Card, CardBody } from "@/components/ui";

/** Per AgentCore call type and agent: volume, latency and failure rates. */
export function AgentCorePanel({ stats }: { stats: AgentCoreStat[] }) {
  const p95s = stats.map(callP95);
  const maxP95 = Math.max(1, ...p95s.map((p) => p.ms));
  return (
    <Card>
      <CardBody className="space-y-3">
        <div>
          <h3 className="text-sm font-semibold text-fg">AgentCore calls</h3>
          <p className="text-[11px] text-muted">
            Harness, Gateway specialist calls and registry lookups, Browser
            sessions and WHOIS lookups
          </p>
        </div>
        {stats.length === 0 && (
          <p className="text-xs text-muted">
            No AgentCore calls in this range.
          </p>
        )}
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted">
                <th className="py-1.5 pr-3 font-medium">Call</th>
                <th className="py-1.5 pr-3 font-medium">Agent</th>
                <th className="py-1.5 pr-3 text-right font-medium">Calls</th>
                <th className="py-1.5 pr-3 text-right font-medium">Avg</th>
                <th className="py-1.5 pr-3 font-medium">p95</th>
                <th className="py-1.5 pr-3 text-right font-medium">Errors</th>
                <th className="py-1.5 text-right font-medium">
                  Guardrail blocks
                </th>
              </tr>
            </thead>
            <tbody>
              {stats.map((s, i) => (
                <tr
                  key={`${s.kind}-${s.name}`}
                  className="border-b border-border/60 last:border-0"
                >
                  <td className="py-2 pr-3 text-fg">{callLabel(s.kind)}</td>
                  <td className="py-2 pr-3 font-mono text-fg-subtle">
                    {s.name}
                  </td>
                  <td className="py-2 pr-3 text-right tabular-nums">
                    {s.count}
                  </td>
                  <td className="py-2 pr-3 text-right tabular-nums">
                    {formatMs(s.avg_ms)}
                  </td>
                  <td className="py-2 pr-3">
                    <div className="flex items-center gap-2">
                      <span className="h-1.5 w-24 rounded-full bg-surface-2">
                        <span
                          className="block h-full rounded-full bg-accent"
                          style={{ width: `${(p95s[i].ms / maxP95) * 100}%` }}
                        />
                      </span>
                      <span data-p95 className="tabular-nums">
                        {p95s[i].text}
                      </span>
                    </div>
                  </td>
                  <td className="py-2 pr-3 text-right tabular-nums">
                    {s.errors}
                  </td>
                  <td className="py-2 text-right tabular-nums">{s.blocked}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardBody>
    </Card>
  );
}
