// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import {
  Check,
  Copy,
  Download,
  FileCode,
  FileText,
  TriangleAlert,
} from "lucide-react";
import { parseInline, parseReport, type ReportBlock } from "@/lib/reportMarkdown";
import { DISCLAIMER_TEXT, DISCLAIMER_TITLE, withDisclaimerMarkdown } from "@/lib/disclaimer";
import type { ReportStatus } from "@/lib/types";
import { useNow } from "@/hooks/useNow";
import { usePrefersReducedMotion } from "@/hooks/usePrefersReducedMotion";
import { cn } from "@/lib/utils";
import {
  elapsedSecondsSince,
  REPORT_FAILED_TEXT,
  REPORT_PENDING_TEXT,
  REPORT_PENDING_TITLE,
  REPORT_TIMEOUT_TEXT,
  REPORT_WAIT_HINT,
} from "@/lib/reportCopy";
import { Button, Card, CardBody } from "./ui";


/**
 * The orchestrator's Markdown report. The formatted view understands only
 * headings, paragraphs, lists, `code` and **bold** (see lib/reportMarkdown) and
 * renders every piece as a React text node: the report quotes hostile page
 * content, so nothing in it may become a link, an image or markup. The verbatim
 * Markdown is one click away, and is what Copy and Download use.
 */
export function ReportPanel({
  report,
  scanId,
  status = "READY",
  startedAt,
  error,
  timedOut = false,
  onCheckAgain,
}: {
  report: string;
  scanId: string;
  /** Absent on records from before the verdict-first split: treated as READY. */
  status?: ReportStatus;
  startedAt?: string | null;
  error?: string | null;
  /** Polling gave up while the report was still PENDING. */
  timedOut?: boolean;
  onCheckAgain?: () => void;
}) {
  if (status === "PENDING") {
    return (
      <ReportPending
        startedAt={startedAt}
        timedOut={timedOut}
        onCheckAgain={onCheckAgain}
      />
    );
  }
  if (status === "FAILED") return <ReportFailed error={error} />;
  return <ReportReady report={report} scanId={scanId} />;
}

function ReportPending({
  startedAt,
  timedOut,
  onCheckAgain,
}: {
  startedAt?: string | null;
  timedOut: boolean;
  onCheckAgain?: () => void;
}) {
  const reduced = usePrefersReducedMotion();
  const now = useNow(1000, !timedOut);
  const mountedAt = useRef(0);
  useEffect(() => {
    mountedAt.current = Date.now();
  }, []);
  const elapsed = elapsedSecondsSince(startedAt, now, mountedAt.current || now);
  return (
    <Card>
      <CardBody
        role="status"
        aria-busy={!timedOut}
        aria-label={REPORT_PENDING_TITLE}
        className="space-y-4"
      >
        {/* Same actions as the ready report, held until there is something to act on. */}
        <div className="flex flex-wrap justify-end gap-2 whitespace-nowrap">
          <span title={REPORT_WAIT_HINT}>
            <Button variant="ghost" size="sm" disabled aria-label={`Copy. ${REPORT_WAIT_HINT}`}>
              <Copy className="h-3.5 w-3.5" /> Copy
            </Button>
          </span>
          <span title={REPORT_WAIT_HINT}>
            <Button variant="ghost" size="sm" disabled aria-label={`Download .md. ${REPORT_WAIT_HINT}`}>
              <Download className="h-3.5 w-3.5" /> Download .md
            </Button>
          </span>
        </div>
        <div>
          <p className="text-sm font-semibold text-fg">{REPORT_PENDING_TITLE}</p>
          <p className="mt-1 max-w-prose text-sm text-fg-subtle">
            {timedOut ? REPORT_TIMEOUT_TEXT : REPORT_PENDING_TEXT}
          </p>
        </div>
        {/* No aria-valuenow: the bar is indeterminate and never claims a percentage. */}
        <div
          role="progressbar"
          aria-label="Report progress, duration unknown"
          data-motion={reduced ? "static" : "animated"}
          className="relative h-1.5 w-full overflow-hidden rounded-full bg-surface-2"
        >
          {reduced || timedOut ? (
            <div className="h-full w-full rounded-full bg-accent/40" />
          ) : (
            <div className="skeleton h-full w-full rounded-full bg-accent/30" />
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs text-fg-subtle">
          {/* aria-live off: a ticking counter inside a live region would chatter. */}
          <span aria-live="off" className="tabular-nums">
            {elapsed}s elapsed
          </span>
          {timedOut && onCheckAgain && (
            <Button variant="secondary" size="sm" onClick={onCheckAgain}>
              Check again
            </Button>
          )}
        </div>
        <div aria-hidden className="space-y-2.5" data-testid="report-skeleton">
          {["w-3/5", "w-full", "w-11/12", "w-4/5"].map((w, i) => (
            <div
              key={i}
              className={cn(
                "h-3 rounded-md bg-surface-2",
                w,
                !reduced && !timedOut && "skeleton",
              )}
            />
          ))}
        </div>
      </CardBody>
    </Card>
  );
}

function ReportFailed({ error }: { error?: string | null }) {
  return (
    <Card>
      <CardBody className="space-y-2">
        <p className="flex items-center gap-2 text-sm font-semibold text-fg">
          <TriangleAlert className="h-4 w-4 text-warn" aria-hidden />
          {REPORT_FAILED_TEXT}
        </p>
        {error?.trim() && (
          <p className="max-w-prose text-xs text-fg-subtle">
            Reason: {error.trim()}
          </p>
        )}
        <p className="max-w-prose text-xs text-fg-subtle">
          <strong className="font-semibold text-fg">{DISCLAIMER_TITLE}.</strong>{" "}
          {DISCLAIMER_TEXT}
        </p>
      </CardBody>
    </Card>
  );
}

function ReportReady({ report, scanId }: { report: string; scanId: string }) {
  const [copied, setCopied] = useState(false);
  const [raw, setRaw] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(withDisclaimerMarkdown(report));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const download = () => {
    const href = URL.createObjectURL(
      new Blob([withDisclaimerMarkdown(report)], { type: "text/markdown" }),
    );
    const a = document.createElement("a");
    a.href = href;
    a.download = `phish-report-${scanId.slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(href);
  };

  return (
    <Card>
      <CardBody className="space-y-3">
        <div className="flex flex-wrap justify-end gap-2 whitespace-nowrap">
          <Button
            variant="ghost"
            size="sm"
            aria-pressed={raw}
            onClick={() => setRaw((r) => !r)}
          >
            {raw ? (
              <FileText className="h-3.5 w-3.5" />
            ) : (
              <FileCode className="h-3.5 w-3.5" />
            )}
            {raw ? "Formatted" : "Markdown"}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => void copy()}>
            {copied ? (
              <Check className="h-3.5 w-3.5" />
            ) : (
              <Copy className="h-3.5 w-3.5" />
            )}
            {copied ? "Copied" : "Copy"}
          </Button>
          <Button variant="ghost" size="sm" onClick={download}>
            <Download className="h-3.5 w-3.5" /> Download .md
          </Button>
        </div>
        {raw ? (
          <pre className="whitespace-pre-wrap wrap-break-word rounded-xl border border-border bg-surface-2/50 p-3 sm:p-4 font-mono text-xs leading-relaxed text-fg">
            {report}
          </pre>
        ) : (
          <FormattedReport blocks={parseReport(report)} />
        )}
      </CardBody>
    </Card>
  );
}

function Inline({ text }: { text: string }) {
  return (
    <>
      {parseInline(text).map((span, i) => {
        if (span.kind === "code")
          return (
            <code
              key={i}
              className="rounded-sm bg-surface-2 px-1 py-0.5 font-mono text-[0.85em]"
            >
              {span.text}
            </code>
          );
        if (span.kind === "strong")
          return (
            <strong key={i} className="font-semibold text-fg">
              {span.text}
            </strong>
          );
        return <span key={i}>{span.text}</span>;
      })}
    </>
  );
}

function FormattedReport({ blocks }: { blocks: ReportBlock[] }) {
  const base = useId();
  const nodes: ReactNode[] = [];
  // A list directly under a heading is named by it, so assistive tech announces
  // "For the recipient, list, 3 items".
  let lastHeadingId: string | undefined;
  blocks.forEach((block, i) => {
    const key = `${base}-${i}`;
    if (block.kind === "heading") {
      lastHeadingId = key;
      nodes.push(
        block.level === 2 ? (
          <h4
            key={key}
            id={key}
            className="border-b border-border pb-1.5 pt-4 text-base font-semibold text-fg first:pt-0"
          >
            <Inline text={block.text} />
          </h4>
        ) : (
          <h5 key={key} id={key} className="pt-1 text-sm font-semibold text-fg">
            <Inline text={block.text} />
          </h5>
        ),
      );
      return;
    }
    const labelledBy = lastHeadingId;
    lastHeadingId = undefined;
    if (block.kind === "rule") {
      nodes.push(<hr key={key} className="border-border" />);
      return;
    }
    if (block.kind === "paragraph") {
      nodes.push(
        <p key={key} className="max-w-prose text-sm leading-relaxed text-fg">
          <Inline text={block.text} />
        </p>,
      );
      return;
    }
    const ListTag = block.ordered ? "ol" : "ul";
    nodes.push(
      <ListTag
        key={key}
        aria-labelledby={labelledBy}
        className={
          (block.ordered ? "list-decimal" : "list-disc") +
          " max-w-prose space-y-1 pl-5 text-sm leading-relaxed text-fg marker:text-fg-subtle"
        }
      >
        {block.items.map((item, j) => (
          <li key={j}>
            <Inline text={item} />
          </li>
        ))}
      </ListTag>,
    );
  });
  // No fixed height: the section is already collapsible, and a scroll box cut
  // the report out of full-page screenshots and print.
  return (
    <div className="space-y-3 wrap-break-word rounded-xl border border-border bg-surface-2/30 p-3 sm:p-5">
      {nodes}
    </div>
  );
}
