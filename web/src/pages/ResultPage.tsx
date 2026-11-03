// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { api } from "@/lib/api";
import { useScanRecord } from "@/hooks/useScan";
import { useNow } from "@/hooks/useNow";
import { deriveProgress, isTerminal } from "@/lib/scanProgress";
import { ResultView } from "@/components/ResultView";
import { GuardrailNotice } from "@/components/GuardrailNotice";
import { RetryButton } from "@/components/RetryButton";
import { StagedProgress } from "@/components/StagedProgress";
import { ErrorState } from "@/components/ui/states";
import { Button, Card, CardBody, Spinner } from "@/components/ui";

/** One scan by id: live progress while running, the full analysis once done. */
export function ResultPage() {
  const { scanId = "" } = useParams();
  const { record, error, retry, reportTimedOut, checkReportAgain } =
    useScanRecord(scanId);
  const running = record !== null && !isTerminal(record.status);
  const now = useNow(1000, running);

  return (
    <div className="space-y-5">
      <Link
        to={
          record?.batch_id
            ? `/batch/${encodeURIComponent(record.batch_id)}`
            : "/history"
        }
        className="inline-flex items-center gap-1.5 text-xs font-medium text-muted transition-colors hover:text-fg"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        {record?.batch_id ? "Back to batch" : "Back to history"}
      </Link>

      {error && (
        <ErrorState
          title="This scan could not be loaded"
          description={error}
          action={
            <Button variant="secondary" onClick={() => void retry()}>
              Retry
            </Button>
          }
        />
      )}

      {!error && record === null && (
        <Card>
          <CardBody className="flex items-center gap-2 text-sm text-muted">
            <Spinner className="h-4 w-4" /> Loading the scan
          </CardBody>
        </Card>
      )}

      {record && running && (
        <StagedProgress
          url={record.url}
          progress={deriveProgress(record, now)}
        />
      )}

      {record?.status === "FAILED" && (
        <>
          <ErrorState
            title="The scan could not complete"
            description={
              record.error?.trim() ||
              "The scan failed without a reason; retry it."
            }
            action={
              <RetryButton
                label="Retry scan"
                onRetry={async () => {
                  await api.retryScan(record.scan_id);
                  // Restart polling: the scan is PENDING again.
                  await retry();
                }}
              />
            }
          />
          <GuardrailNotice events={record.guardrail_events} />
        </>
      )}

      {record?.status === "COMPLETE" && record.verdict && (
        <ResultView
          record={record}
          reportTimedOut={reportTimedOut}
          onCheckReport={checkReportAgain}
        />
      )}
    </div>
  );
}
