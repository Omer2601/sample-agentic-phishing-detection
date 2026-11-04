// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clampScore,
  formatCost,
  formatDuration,
  formatMs,
  formatP95,
  formatRelativeTime,
  formatTokens,
  normalizeUrl,
  scoreBand,
  shortId,
  validateUrl,
} from "./utils";

describe("scores", () => {
  it("clamps into 0..100", () => {
    expect(clampScore(-3)).toBe(0);
    expect(clampScore(101.6)).toBe(100);
    expect(clampScore(42.4)).toBe(42);
  });
  it("bands scores", () => {
    expect(scoreBand(70)).toBe("danger");
    expect(scoreBand(35)).toBe("warn");
    expect(scoreBand(34)).toBe("safe");
  });
});

describe("durations", () => {
  it("formats seconds", () => {
    expect(formatDuration(34.4)).toBe("34s");
    expect(formatDuration(125)).toBe("2m 05s");
    expect(formatDuration(35_628)).toBe("9h 53m");
  });
  it("formats milliseconds", () => {
    expect(formatMs(850)).toBe("850 ms");
    expect(formatMs(34_400)).toBe("34s");
    expect(formatMs(null)).toBe("n/a");
  });
});

// Parse what formatDuration prints back into whole seconds, and check it never
// prints an out-of-range unit ("1m 60s", "1h 60m").
function parsed(text: string): { seconds: number; ok: boolean } {
  const h = /^(\d+)h (\d{2})m$/.exec(text);
  if (h) return { seconds: +h[1] * 3600 + +h[2] * 60, ok: +h[2] < 60 };
  const m = /^(\d+)m (\d{2})s$/.exec(text);
  if (m) return { seconds: +m[1] * 60 + +m[2], ok: +m[1] < 60 && +m[2] < 60 };
  const s = /^(\d+)s$/.exec(text);
  if (s) return { seconds: +s[1], ok: +s[1] < 60 };
  return { seconds: Number.NaN, ok: false };
}

describe("duration rounding at unit boundaries", () => {
  it("rolls 119.6 s over to 2m 00s, not 1m 60s (UI e2e run 2, D5)", () => {
    expect(formatDuration(119.6)).toBe("2m 00s");
    expect(formatDuration(59.6)).toBe("1m 00s");
    expect(formatDuration(3599.6)).toBe("1h 00m");
    expect(formatMs(119_600)).toBe("2m 00s");
  });

  it("never prints an out-of-range unit and stays within a second below an hour", () => {
    // Every tenth of a second either side of each minute boundary up to an hour.
    for (let minute = 1; minute <= 60; minute += 1) {
      for (let tenth = -10; tenth <= 10; tenth += 1) {
        const seconds = minute * 60 + tenth / 10;
        const out = parsed(formatDuration(seconds));
        expect(out.ok, `${seconds} -> ${formatDuration(seconds)}`).toBe(true);
        if (seconds < 3599.5) {
          expect(Math.abs(out.seconds - seconds)).toBeLessThanOrEqual(0.5);
        }
      }
    }
  });

  it("is monotonic across minute boundaries", () => {
    let last = -1;
    for (let tenths = 0; tenths <= 36_100; tenths += 3) {
      const out = parsed(formatDuration(tenths / 10));
      expect(out.seconds).toBeGreaterThanOrEqual(last);
      last = out.seconds;
    }
  });

  it("rounds sub-second values up into seconds, not 1000 ms", () => {
    expect(formatMs(999.6)).toBe("1s");
    expect(formatMs(999.4)).toBe("999 ms");
  });
});

describe("cost and tokens", () => {
  it("shows four decimals under a dollar", () => {
    expect(formatCost("0.14321")).toBe("$0.1432");
    expect(formatCost(0)).toBe("$0.0000");
  });
  it("shows two decimals from a dollar up", () => {
    expect(formatCost("7.4812")).toBe("$7.48");
  });
  it("treats unparseable input as zero rather than NaN", () => {
    expect(formatCost("abc")).toBe("$0.0000");
  });
  it("abbreviates tokens", () => {
    expect(formatTokens(950)).toBe("950");
    expect(formatTokens(12_345)).toBe("12.3k");
    expect(formatTokens(4_200_000)).toBe("4.2M");
  });
});

describe("relative time", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-29T12:00:00Z"));
  });
  afterEach(() => {
    vi.useRealTimers();
  });
  it("describes recent times", () => {
    expect(formatRelativeTime("2026-09-29T11:59:40Z")).toBe("just now");
    expect(formatRelativeTime("2026-09-29T11:15:00Z")).toBe("45m ago");
    expect(formatRelativeTime("2026-09-28T12:00:00Z")).toBe("1d ago");
  });
});

describe("urls", () => {
  it("adds https to bare hosts", () => {
    expect(normalizeUrl(" example.com ")).toBe("https://example.com");
    expect(normalizeUrl("http://a.b")).toBe("http://a.b");
  });
  it("validates scheme and host", () => {
    expect(validateUrl("ftp://a.b")).toMatch(/http and https/);
    expect(validateUrl("localhost")).toMatch(/fully-qualified/);
    expect(validateUrl("https://ok.example")).toBeNull();
  });
  it("shortens ids", () => {
    expect(shortId("9d9baee7-16f2-4718")).toBe("9d9baee7");
  });

describe("formatP95", () => {
  it("shows the number when p95 is within the latency buckets", () => {
    expect(formatP95(47_000, false)).toBe("47s");
    expect(formatP95(47_000, undefined)).toBe("47s");
  });

  it("says over 2m when the backend flags p95 above 120 s", () => {
    expect(formatP95(120_000, true)).toBe("over 2m");
  });

  it("presents a bucket-edge p95 as a bound, not a measurement", () => {
    expect(formatP95(10_000, false, true)).toBe("under 10s");
    expect(formatP95(3_000, false, true)).toBe("under 10s");
    expect(formatP95(40_000, false, true)).toBe("up to 40s");
    expect(formatP95(35_000, false, false)).toBe("35s");
  });
});
});
