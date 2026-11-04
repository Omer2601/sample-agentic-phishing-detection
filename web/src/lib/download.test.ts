// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { isReportLink } from "./download";

describe("isReportLink", () => {
  it("accepts only https links", () => {
    expect(isReportLink("https://bucket.s3.us-west-2.amazonaws.com/r.html?X=1")).toBe(true);
    expect(isReportLink("http://bucket.s3.amazonaws.com/r.html")).toBe(false);
    expect(isReportLink("javascript:alert(1)")).toBe(false);
    expect(isReportLink("not a url")).toBe(false);
  });
});
