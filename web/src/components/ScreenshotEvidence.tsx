// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from "react";
import { Camera, ImageOff } from "lucide-react";
import { describeSignal } from "@/lib/signals";
import type { Finding } from "@/lib/types";
import { Card, CardBody } from "./ui";

/** The page as the brand and visual agent saw it in AgentCore Browser, beside its top signals. */
export function ScreenshotEvidence({
  src,
  finding,
}: {
  src: string | null;
  finding?: Finding;
}) {
  const [broken, setBroken] = useState(false);
  const top = (finding?.signals ?? []).slice(0, 3);
  // The image is a presigned S3 URL, so the caption speaks about that link and
  // only when there is one; with no capture there is nothing to expire.
  const caption = !src
    ? "No screenshot was captured for this scan."
    : broken
      ? "The screenshot link has expired. Reload the page for a fresh one."
      : "Isolated render. The image link expires after a few minutes.";
  return (
    <Card>
      <CardBody>
        <div className="mb-4 flex items-center gap-2">
          <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-accent/15 text-accent">
            <Camera className="h-4 w-4" aria-hidden />
          </span>
          <p className="text-sm font-semibold text-fg">
            Captured page and brand check
          </p>
        </div>
        <div className="grid gap-5 md:grid-cols-2">
          {/* One fixed 16:10 frame for the image, the loading state and the
              empty state, so the panel never jumps when the lazy image arrives
              or fails. The capture is a full page; its top is what matters. */}
          <figure className="overflow-hidden rounded-xl border border-border bg-surface-2">
            <div className="relative aspect-16/10 w-full">
              {src && !broken ? (
                <img
                  src={src}
                  alt="The analysed page as rendered in an isolated AgentCore browser"
                  className="absolute inset-0 h-full w-full object-cover object-top"
                  loading="lazy"
                  onError={() => setBroken(true)}
                />
              ) : (
                <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 px-6 text-center text-muted">
                  <ImageOff className="h-8 w-8" aria-hidden />
                  <span className="text-sm font-medium text-fg-subtle">
                    Screenshot unavailable
                  </span>
                </div>
              )}
            </div>
            <figcaption className="space-y-1 border-t border-border px-3 py-2">
              {/* Written by code, not the model: how the capture went (bot
                  check, Cloudflare warning, browser refusal). Plain text. */}
              {finding?.capture_note && (
                <p className="text-xs leading-relaxed text-fg-subtle">
                  {finding.capture_note}
                </p>
              )}
              <p className="text-[11px] text-muted">{caption}</p>
            </figcaption>
          </figure>
          <ul className="space-y-3 text-sm leading-relaxed text-fg-subtle">
            {top.length === 0 && (
              <li className="text-muted">
                No brand or visual signals recorded.
              </li>
            )}
            {top.map((s, i) => (
              <li key={`${s.name}-${i}`}>
                <span className="font-medium text-fg">
                  {describeSignal(s.name).title}.
                </span>{" "}
                {s.evidence}
              </li>
            ))}
          </ul>
        </div>
      </CardBody>
    </Card>
  );
}
