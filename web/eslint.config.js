// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// ESLint flat config for a Vite + React 18 + TypeScript (strict) SPA.
//
// This project shipped a `lint` script that invoked eslint while eslint was not
// installed, so linting silently passed and caught nothing before going to a
// public samples repo. This config makes linting real. It leans on the
// type-unaware typescript-eslint recommended set (fast, no typed-linting project
// wiring needed) plus the React Hooks rules, which protect against the class of
// runtime bug the type checker cannot see (conditional or miswired hooks).
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";

export default tseslint.config(
  // Build output and dependency trees are not ours to lint.
  {
    ignores: [
      "dist",
      "build",
      "node_modules",
      "devproxy",
      "server",
      "*.config.js",
      "*.config.ts",
    ],
  },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Fast-refresh only works when a module exports components exclusively.
      // Warn rather than error: shared constant-plus-component files are common
      // here and are not bugs.
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
      // Unused vars are real dead code, but an underscore prefix is the
      // conventional, intentional "deliberately ignored" marker (constructor
      // config, catch bindings), so exempt it.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  // Test files legitimately assert against loosely typed API payloads, so the
  // explicit-any brake would fight the tests rather than protect them.
  {
    files: ["**/*.test.{ts,tsx}"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
);
