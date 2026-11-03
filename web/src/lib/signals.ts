// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// A byte-identical copy of contracts/phish_contracts/signal_catalog.json, owned
// by the contracts package (tests/test_signal_catalog_copy.py). Do not edit here.
import shippedCatalog from "./signalCatalog.json";

/** Shape of signalCatalog.json, a copy of contracts/phish_contracts/signal_catalog.json. */
export type SignalCatalog = Record<string, { title: string; explain: string }>;

export interface SignalCopy {
  title: string;
  /** Plain-English explanation for an analyst; null when the catalog has none. */
  explain: string | null;
}

/**
 * Model signal names are free-form snake_case ("eval_or_function_constructor").
 * Turn one into a sentence-case phrase. Only the first letter changes case, so
 * acronyms (TLD, JS) and names that are already prose survive.
 */
export function humanizeSignalName(name: string): string {
  const words = name.replace(/[_-]+/g, " ").trim().replace(/\s+/g, " ");
  if (!words) return "Unnamed signal";
  return words.charAt(0).toUpperCase() + words.slice(1);
}

const SIGNAL_CATALOG: SignalCatalog = shippedCatalog;

/** Exact name first, then trimmed lowercase, like phish_contracts.signals._entry. */
function lookup(catalog: SignalCatalog, name: string) {
  // Object.hasOwn: a signal named "constructor" must not read Object.prototype.
  for (const key of [name, name.trim().toLowerCase()]) {
    if (Object.hasOwn(catalog, key)) return catalog[key];
  }
  return undefined;
}

/** Analyst-facing title and explanation for a signal name. */
export function describeSignal(
  name: string,
  catalog: SignalCatalog = SIGNAL_CATALOG,
): SignalCopy {
  const entry = lookup(catalog, name);
  if (entry?.title)
    return { title: entry.title, explain: entry.explain || null };
  return { title: humanizeSignalName(name), explain: null };
}

/**
 * Defang a URL for display (hxxps, [.]). The backend already defangs insight
 * URLs; this is a second, idempotent pass so a missed one is never copyable as
 * a live link.
 */
export function defang(text: string): string {
  return text
    .replace(/\bhttp(s?):\/\//gi, "hxxp$1://")
    .replace(/(?<!\[)\.(?!\])/g, "[.]");
}
