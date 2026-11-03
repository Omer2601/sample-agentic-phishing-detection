// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useEffect, useState } from "react";

const QUERY = "(prefers-reduced-motion: reduce)";

function read(): boolean {
  return typeof window.matchMedia === "function"
    ? window.matchMedia(QUERY).matches
    : false;
}

/**
 * True when the user asked for reduced motion. The global CSS already shortens
 * animations; components use this to swap an animated element for a static one
 * rather than a frozen mid-frame animation.
 */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(read);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(QUERY);
    const onChange = () => setReduced(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  return reduced;
}
