// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { FileClock } from "lucide-react";
import { isReportPending } from "@/lib/scanProgress";
import type { ScanRecord } from "@/lib/types";

/**
 * A subtle note on a table row whose verdict is in but whose full report is still
 * being written. Renders nothing otherwise, so older records (no report_status)
 * and READY or FAILED reports look exactly as before.
 */
export function ReportPendingHint({
  item,
}: {
  item: Pick<ScanRecord, "status" | "report_status">;
}) {
  if (!isReportPending(item)) return null;
  return (
    <span
      className="inline-flex items-center gap-1 text-[11px] text-fg-subtle"
      title="The verdict is ready; the full report is still being written."
    >
      <FileClock className="h-3 w-3" aria-hidden />
      <span>Report pending</span>
    </span>
  );
}
