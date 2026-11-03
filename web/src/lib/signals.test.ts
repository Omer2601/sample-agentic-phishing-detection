// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from "vitest";
import { defang, describeSignal, humanizeSignalName } from "./signals";

const catalog = {
  telegram_bot_exfil: {
    title: "Sends typed passwords to a Telegram bot",
    explain: "The page posts form data to the Telegram bot API.",
  },
};

describe("humanizeSignalName", () => {
  it("turns model snake_case into a sentence-case phrase", () => {
    expect(humanizeSignalName("eval_or_function_constructor")).toBe(
      "Eval or function constructor",
    );
  });

  it("keeps acronyms and collapses separators", () => {
    expect(humanizeSignalName("  suspicious__TLD-match ")).toBe(
      "Suspicious TLD match",
    );
  });

  it("leaves an already readable name alone", () => {
    expect(humanizeSignalName("Typosquat of google.com")).toBe(
      "Typosquat of google.com",
    );
  });

  it("never returns an empty title", () => {
    expect(humanizeSignalName("___")).toBe("Unnamed signal");
  });
});

describe("describeSignal", () => {
  it("uses the catalog title and explanation when the name is known", () => {
    expect(describeSignal("telegram_bot_exfil", catalog)).toEqual({
      title: "Sends typed passwords to a Telegram bot",
      explain: "The page posts form data to the Telegram bot API.",
    });
  });

  it("falls back to a humanized name with no explanation", () => {
    expect(describeSignal("devtools_evasion", catalog)).toEqual({
      title: "Devtools evasion",
      explain: null,
    });
  });

  it("matches a name that differs only in case or surrounding space", () => {
    expect(describeSignal(" Telegram_Bot_Exfil", catalog).title).toBe(
      "Sends typed passwords to a Telegram bot",
    );
  });

  it("reads the shipped catalog by default", () => {
    expect(describeSignal("blocked_by_browser").title).toBe(
      "The isolated browser refused to open this URL",
    );
    expect(describeSignal("blocked_by_browser").explain).toMatch(/not evidence of phishing/);
  });

  it("does not read inherited object keys as catalog entries", () => {
    expect(describeSignal("constructor", catalog).title).toBe("Constructor");
    expect(describeSignal("__proto__", catalog).explain).toBeNull();
  });
});

describe("defang", () => {
  it("defangs scheme and dots", () => {
    expect(defang("https://evil.example/a.php")).toBe(
      "hxxps://evil[.]example/a[.]php",
    );
  });

  it("is idempotent on backend-defanged text", () => {
    const once = "hxxps://api[.]telegram[.]org/bot";
    expect(defang(once)).toBe(once);
    expect(defang(defang("http://a.b"))).toBe("hxxp://a[.]b");
  });
});
