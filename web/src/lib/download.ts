// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/** Presigned S3 links are always https; anything else is never followed. */
export function isReportLink(href: string): boolean {
  try {
    return new URL(href).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Follow a presigned report link. The object is served with
 * Content-Disposition: attachment, so the browser saves it and this page stays.
 */
export function startDownload(href: string): void {
  if (!isReportLink(href)) throw new Error("The report link is not https.");
  const a = document.createElement("a");
  a.href = href;
  a.rel = "noopener noreferrer";
  a.click();
}
