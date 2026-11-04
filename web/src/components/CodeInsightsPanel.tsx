// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useId } from "react";
import { FileCode2 } from "lucide-react";
import type { Finding } from "@/lib/types";
import { defang } from "@/lib/signals";
import { Badge, Card, CardBody } from "./ui";

/**
 * What the page's code does, from code_analyst's measured insights: where it
 * sends data, its forms and its scripts. Every value comes from the scanned page, so it is
 * rendered as plain text (defanged), never as a link or markup.
 */
export function CodeInsightsPanel({ finding }: { finding?: Finding }) {
  const headingId = useId();
  const insights = finding?.insights;
  if (!insights) return null;
  const endpoints = insights.endpoints ?? [];
  const forms = insights.forms ?? [];
  const hosts = insights.external_script_hosts ?? [];
  return (
    <section aria-labelledby={headingId}>
      <Card>
        <CardBody className="space-y-5">
          <div className="flex items-center gap-3">
            <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent/15 text-accent">
              <FileCode2 className="h-4 w-4" aria-hidden />
            </span>
            <div className="min-w-0">
              <h4 id={headingId} className="text-base font-semibold text-fg">
                What the page's code does
              </h4>
              <p className="text-xs text-muted">
                Measured in the isolated browser; the page is observed, never filled in
              </p>
            </div>
          </div>

          <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs font-medium text-muted">Scripts</dt>
              <dd className="tabular-nums text-fg">
                {insights.script_count ?? 0} scripts, {insights.script_kb ?? 0}{" "}
                KB
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs font-medium text-muted">
                External script hosts
              </dt>
              <dd className="break-words text-fg">
                {hosts.length > 0 ? hosts.join(", ") : "None"}
              </dd>
            </div>
          </dl>

          <div className="space-y-2">
            <p className="text-sm font-semibold text-fg">
              Where the code sends data
            </p>
            {endpoints.length === 0 ? (
              <p className="text-sm text-muted">No requests recorded.</p>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-left text-sm">
                  <thead className="bg-surface-2 text-xs text-fg-subtle">
                    <tr>
                      <th scope="col" className="px-3 py-2 font-medium">
                        Address
                      </th>
                      <th scope="col" className="px-3 py-2 font-medium">
                        Kind
                      </th>
                      <th scope="col" className="px-3 py-2 font-medium">
                        Marks
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {endpoints.map((e, i) => (
                      <tr key={`${e.url}-${i}`} className="align-top">
                        <td className="w-1/2 px-3 py-2 font-mono text-xs break-all text-fg">
                          {defang(e.url)}
                        </td>
                        <td className="px-3 py-2 text-fg-subtle">{e.kind}</td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap gap-1.5">
                            {e.off_domain ? (
                              <Badge tone="warn">Off-domain</Badge>
                            ) : (
                              <Badge>Same site</Badge>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="space-y-2">
            <p className="text-sm font-semibold text-fg">Forms</p>
            {forms.length === 0 ? (
              <p className="text-sm text-muted">No forms found.</p>
            ) : (
              <ul className="space-y-2">
                {forms.map((f, i) => (
                  <li
                    key={`${f.action}-${i}`}
                    className="space-y-1 rounded-xl border border-border px-3 py-2 text-sm"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs break-all text-fg">
                        {f.action
                          ? defang(f.action)
                          : "No action (stays on the page)"}
                      </span>
                      {f.submits_via_js && (
                        <Badge tone="warn">Submitted by script</Badge>
                      )}
                    </div>
                    <p className="text-xs text-fg-subtle">
                      <span className="text-muted">Fields: </span>
                      <span>
                        {f.fields?.length ? f.fields.join(", ") : "none"}
                      </span>
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </CardBody>
      </Card>
    </section>
  );
}
