// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  ChevronRight,
  Clock,
  History as HistoryIcon,
  Layers,
  ScanLine,
} from "lucide-react";
import { api } from "@/lib/api";
import type { ScanRecord } from "@/lib/types";
import { formatCost, formatMs, formatRelativeTime } from "@/lib/utils";
import { useActiveBatches } from "@/hooks/useActiveBatches";
import { useNow } from "@/hooks/useNow";
import { BatchRow } from "@/components/BatchRow";
import { ReportPendingHint } from "@/components/ReportPendingHint";
import { RiskPill, VerdictBadge } from "@/components/VerdictBadge";
import { Button, Card, CardBody, Skeleton } from "@/components/ui";
import { Tabs } from "@/components/ui/Tabs";
import { EmptyState, ErrorState } from "@/components/ui/states";

function ScanList() {
  const [items, setItems] = useState<ScanRecord[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [state, setState] = useState<"loading" | "loaded" | "error">("loading");
  const [more, setMore] = useState(false);

  const load = useCallback(async (token: string | null) => {
    try {
      const page = await api.getHistory(token);
      setItems((prev) => (token ? [...prev, ...page.items] : page.items));
      setNext(page.next);
      setState("loaded");
    } catch {
      // A failed first page is shown as the error state; a failed "load more"
      // keeps the rows already on screen and shows the same state below them.
      setState("error");
    }
  }, []);

  useEffect(() => {
    void load(null);
  }, [load]);

  if (state === "loading") {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full rounded-2xl" />
        ))}
      </div>
    );
  }
  if (state === "error" && items.length === 0) {
    return (
      <ErrorState description="Could not load your scan history. Please try again." />
    );
  }
  if (items.length === 0) {
    return (
      <EmptyState
        icon={<HistoryIcon className="h-6 w-6" />}
        title="No scans yet"
        description="Run your first scan and it will show up here."
      />
    );
  }
  return (
    <div className="space-y-3">
      <Card>
        <CardBody className="p-0">
          <ul className="divide-y divide-border">
            {items.map((item) => (
              <li key={item.scan_id}>
                <Link
                  to={`/results/${encodeURIComponent(item.scan_id)}`}
                  className="flex flex-col gap-3 px-5 py-4 transition-colors hover:bg-surface-2/40 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="min-w-0">
                    <p
                      className="truncate font-mono text-sm text-fg"
                      title={item.url}
                    >
                      {item.url}
                    </p>
                    <p className="mt-1 inline-flex items-center gap-1.5 text-xs text-muted">
                      <Clock className="h-3 w-3" aria-hidden />
                      {formatRelativeTime(item.queued_at)},{" "}
                      {formatMs(item.total_ms)}, {formatCost(item.cost_usd)}
                      {item.batch_id ? ", in a batch" : ""}
                    </p>
                    <ReportPendingHint item={item} />
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    {item.verdict ? (
                      <>
                        <VerdictBadge verdict={item.verdict.verdict} />
                        <RiskPill score={item.verdict.risk_score} />
                      </>
                    ) : (
                      <span className="text-xs text-muted">
                        {item.status.toLowerCase()}
                      </span>
                    )}
                    <ChevronRight className="h-4 w-4 text-muted" aria-hidden />
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        </CardBody>
      </Card>
      {state === "error" && (
        <p className="text-xs text-danger">
          Could not load more scans. Try again.
        </p>
      )}
      {next && (
        <div className="flex justify-center">
          <Button
            variant="secondary"
            disabled={more}
            onClick={async () => {
              setMore(true);
              await load(next);
              setMore(false);
            }}
          >
            Load more
          </Button>
        </div>
      )}
    </div>
  );
}

function BatchList() {
  const { batches, active, loaded } = useActiveBatches();
  const now = useNow(1000, active.length > 0);
  if (loaded && batches.length === 0) {
    return (
      <EmptyState
        icon={<Layers className="h-6 w-6" />}
        title="No batches yet"
        description="Batches you submit appear here."
      />
    );
  }
  return (
    <Card>
      <CardBody className="divide-y divide-border p-0">
        {batches.map((b) => (
          <BatchRow key={b.batch_id} batch={b} now={now} />
        ))}
      </CardBody>
    </Card>
  );
}

export function HistoryPage() {
  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-fg">
            History
          </h1>
          <p className="mt-1 text-sm text-fg-subtle">
            Every scan and batch you have run, newest first.
          </p>
        </div>
        <Link
          to="/"
          className="hidden items-center gap-2 rounded-xl border border-border bg-surface-2 px-4 py-2 text-sm font-medium text-fg transition-colors hover:bg-surface-2/70 sm:inline-flex"
        >
          <ScanLine className="h-4 w-4" /> New scan
        </Link>
      </header>
      <Tabs
        label="History views"
        items={[
          { id: "scans", label: "Scans", content: <ScanList /> },
          { id: "batches", label: "Batches", content: <BatchList /> },
        ]}
      />
    </div>
  );
}
