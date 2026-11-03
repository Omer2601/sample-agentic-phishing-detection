// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Clock, Coins, Cpu } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "@/lib/api";
import { reportStatusOf } from "@/lib/scanProgress";
import type { ScanDetail } from "@/lib/types";
import { scanTokens } from "@/lib/timeline";
import { formatCost, formatMs, formatTokens, shortId } from "@/lib/utils";
import { AgentTimeline } from "./AgentTimeline";
import { CodeInsightsPanel } from "./CodeInsightsPanel";
import { GuardrailNotice } from "./GuardrailNotice";
import { PageNotObservedNotice } from "./PageNotObservedNotice";
import { RedirectChainPanel } from "./RedirectChainPanel";
import { REPORT_WAIT_HINT } from "@/lib/reportCopy";
import { ReportPanel } from "./ReportPanel";
import { ReportDownloadButton } from "./ReportDownloadButton";
import { ScreenshotEvidence } from "./ScreenshotEvidence";
import { SimilarScans } from "./SimilarScans";
import { SpecialistRadar } from "./SpecialistRadar";
import { SpecialistSummary } from "./SpecialistSummary";
import { VerdictHero } from "./VerdictHero";
import { Collapsible } from "./ui";

export function ResultView({
  record,
  reportTimedOut = false,
  onCheckReport,
}: {
  record: ScanDetail;
  /** Report polling gave up; the placeholder says so and offers another check. */
  reportTimedOut?: boolean;
  onCheckReport?: () => void;
}) {
  const verdict = record.verdict;
  if (!verdict) return null;
  const reportStatus = reportStatusOf(record);
  const reportPending = reportStatus === "PENDING";
  const tokens = scanTokens(record);
  // cost_usd is a Decimal string; an empty or zero value means the cost is not
  // known yet, and "$0.0000" would read as a real (free) price, so show nothing.
  const cost = Number.parseFloat(record.cost_usd);
  const hasCost = Number.isFinite(cost) && cost > 0;
  // A model with no price is not free: say the cost is unknown instead of a low number.
  const unpriced = record.unpriced_models ?? [];
  return (
    <div className="space-y-6 animate-fade-in">
      <VerdictHero url={record.url} verdict={verdict} />
      <PageNotObservedNotice verdict={verdict} findings={record.findings} />
      <GuardrailNotice events={record.guardrail_events} />

      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-xl border border-border bg-surface-2/40 px-4 py-2.5 text-xs text-fg-subtle">
        <span className="inline-flex items-center gap-1.5">
          <Clock className="h-3.5 w-3.5" aria-hidden />{" "}
          {formatMs(record.total_ms)} total
          {record.queue_wait_ms
            ? ` (${formatMs(record.queue_wait_ms)} queued)`
            : ""}
        </span>
        {unpriced.length > 0 ? (
          <span
            className="inline-flex items-center gap-1.5"
            title={`No price for ${unpriced.join(", ")}`}
          >
            <Coins className="h-3.5 w-3.5" aria-hidden /> Token cost unknown
            (no price for {unpriced.join(", ")})
          </span>
        ) : hasCost ? (
          <span className="inline-flex items-center gap-1.5">
            <Coins className="h-3.5 w-3.5" aria-hidden />{" "}
            {formatCost(cost)} in tokens
          </span>
        ) : null}
        <span className="inline-flex items-center gap-1.5">
          <Cpu className="h-3.5 w-3.5" aria-hidden />{" "}
          {formatTokens(tokens.input)} in, {formatTokens(tokens.output)} out
        </span>
        <span className="font-mono text-muted">
          scan {shortId(record.scan_id)}
        </span>
        {record.batch_id && (
          <Link
            to={`/batch/${encodeURIComponent(record.batch_id)}`}
            className="text-accent hover:underline"
          >
            Part of batch {shortId(record.batch_id)}
          </Link>
        )}
        {/* The download sits with the scan facts it summarises, not on a row of its own. */}
        <div className="ml-auto">
          <ReportDownloadButton
            fetchLink={() => api.getScanReport(record.scan_id)}
            disabledReason={reportPending ? REPORT_WAIT_HINT : undefined}
          />
        </div>
      </div>

      <section aria-label="Report">
        <Collapsible
          title="Orchestrator report"
          subtitle="How the judge weighed the specialists, and what to do next"
          defaultOpen
        >
          <ReportPanel
            report={verdict.report_markdown}
            scanId={record.scan_id}
            status={reportStatus}
            startedAt={record.report_started_at}
            error={record.report_error}
            timedOut={reportTimedOut}
            onCheckAgain={onCheckReport}
          />
        </Collapsible>
      </section>

      <section aria-label="Specialists" className="space-y-4">
        <h3 className="text-lg font-bold tracking-tight text-fg">
          Specialists
        </h3>
        <SpecialistRadar findings={record.findings} />
        <SpecialistSummary findings={record.findings} verdict={verdict} />
        <RedirectChainPanel findings={record.findings} />
        <CodeInsightsPanel
          finding={record.findings.find((f) => f.agent === "code_analyst")}
        />
      </section>

      <section aria-label="AgentCore timeline">
        <Collapsible
          title="AgentCore timeline"
          subtitle="Every harness, agent, browser and WHOIS call"
          defaultOpen={false}
        >
          <AgentTimeline record={record} />
        </Collapsible>
      </section>

      <section aria-label="Visual capture">
        <Collapsible
          title="Visual capture"
          subtitle="Rendered page and brand check"
          defaultOpen={false}
        >
          <ScreenshotEvidence
            src={record.artifacts.screenshot}
            finding={record.findings.find((f) => f.agent === "brand_visual")}
          />
        </Collapsible>
      </section>

      {record.similar_scans?.length ? (
        <section aria-label="Similar past scans">
          <Collapsible
            title="Similar past scans"
            subtitle="Context from episodic memory, not evidence"
            defaultOpen={false}
          >
            <SimilarScans scans={record.similar_scans} />
          </Collapsible>
        </section>
      ) : null}
    </div>
  );
}
