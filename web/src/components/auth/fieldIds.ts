// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * Element ids for the auth form fields.
 *
 * A one-function module rather than a constant exported from Fields.tsx, so that
 * file stays components-only and keeps its fast-refresh boundary intact.
 *
 * The ids are derived from the field name instead of useId because two things
 * need to agree on them: the <label htmlFor> wiring inside the field components,
 * and the page's "focus the first field in error" behaviour on a failed submit.
 * A stable, predictable id is what lets the second one exist without threading a
 * ref through every field.
 */
export function fieldElementId(name: string): string {
  return `field-${name}`;
}
