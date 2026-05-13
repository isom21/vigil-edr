// Flat ESLint config for the EDR frontend.
//
// Keeps the rule surface small: TypeScript + React-hooks + React-refresh.
// Tightens up later as the codebase grows; for now we want CI green
// without spurious warnings on existing M0..M7 code.

import js from "@eslint/js";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";

export default [
  js.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      parser: tsparser,
      ecmaVersion: 2022,
      sourceType: "module",
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
      globals: {
        window: "readonly",
        document: "readonly",
        console: "readonly",
        fetch: "readonly",
        navigator: "readonly",
        localStorage: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        HTMLElement: "readonly",
        HTMLInputElement: "readonly",
        HTMLButtonElement: "readonly",
        HTMLDivElement: "readonly",
        Element: "readonly",
        AbortSignal: "readonly",
        Response: "readonly",
        Request: "readonly",
        FormData: "readonly",
        Blob: "readonly",
        File: "readonly",
        process: "readonly",
        React: "readonly",
        // Phase 1 #1.4 — live-response remote shell needs WebSocket
        // + binary string conversion helpers from the browser env.
        WebSocket: "readonly",
        TextEncoder: "readonly",
        atob: "readonly",
        btoa: "readonly",
      },
    },
    plugins: {
      "@typescript-eslint": tseslint,
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // We use `any` deliberately in protobuf glue and shadcn primitives.
      "@typescript-eslint/no-explicit-any": "off",
      "no-empty-pattern": "off",
    },
  },
  {
    ignores: ["dist", "node_modules", "src/components/ui/**"],
  },
];
