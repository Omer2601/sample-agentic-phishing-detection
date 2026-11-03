// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * The three glyphs the registration screen needs, hand-rolled.
 *
 * They are written out here rather than imported from the icon package because
 * each new icon import adds to the initial bundle, and this screen is the first
 * thing an unauthenticated visitor downloads. Every icon is decorative: the
 * meaning is always carried by adjacent text or by the control's own accessible
 * name, so each one is aria-hidden and contributes nothing to the accessibility
 * tree.
 */

interface IconProps {
  className?: string;
}

/** Tick shown when a password rule is satisfied. */
export function CheckIcon({ className }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M4.5 12.5 9.5 17.5 19.5 6.5" />
    </svg>
  );
}
