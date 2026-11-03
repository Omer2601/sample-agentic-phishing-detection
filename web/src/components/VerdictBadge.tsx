// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import {
  CircleHelp,
  FileX2,
  ServerOff,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";
import type { VerdictLabel } from "@/lib/types";
import { VERDICT_STYLE } from "@/lib/verdictStyle";
import { cn, scoreBand } from "@/lib/utils";
import { Badge } from "./ui";

export function VerdictIcon({
  verdict,
  className,
}: {
  verdict: VerdictLabel;
  className?: string;
}) {
  if (verdict === "phishing")
    return <ShieldAlert className={className} aria-hidden />;
  if (verdict === "suspicious")
    return <ShieldQuestion className={className} aria-hidden />;
  if (verdict === "legitimate")
    return <ShieldCheck className={className} aria-hidden />;
  if (verdict === "error_404")
    return <FileX2 className={className} aria-hidden />;
  if (verdict === "site_down")
    return <ServerOff className={className} aria-hidden />;
  return <CircleHelp className={className} aria-hidden />;
}

export function VerdictBadge({ verdict }: { verdict: VerdictLabel }) {
  const style = VERDICT_STYLE[verdict];
  return (
    <Badge tone={style.token}>
      <VerdictIcon verdict={verdict} className="h-3.5 w-3.5" />
      {style.label}
    </Badge>
  );
}

export function RiskPill({ score }: { score: number }) {
  const band = scoreBand(score);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums",
        band === "danger" && "bg-danger/15 text-danger",
        band === "warn" && "bg-warn/15 text-warn",
        band === "safe" && "bg-safe/15 text-safe",
      )}
    >
      {score}
      <span className="text-[10px] font-normal opacity-70">/100</span>
    </span>
  );
}
