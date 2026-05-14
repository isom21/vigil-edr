#!/usr/bin/env bash
# Regression test for LIVE-3 / CODE-301.
#
# The original gate was `npx tsc --noEmit` against the root tsconfig.json,
# which has `"files": []` and no `include` — so it silently checks zero
# files and exits 0 no matter what the code looks like. That's how the 54
# type errors in LIVE-2 (broken Select API + PageHeader + Checkbox + the
# `alert.summary_ready` Webhooks record) sailed through CI.
#
# This script temporarily injects a deliberately broken named-import into
# Allowlist.tsx, runs the typecheck gate, and asserts the gate fails. If
# the gate exits 0 against obviously broken code, the gate is a no-op
# again and we want CI to refuse the merge.
set -euo pipefail

cd "$(dirname "$0")/.."

target=src/pages/Allowlist.tsx
if [[ ! -f $target ]]; then
  echo "verify-typecheck-gate: $target missing — adjust the script" >&2
  exit 1
fi

backup=$(mktemp)
trap 'mv "$backup" "$target"' EXIT
cp "$target" "$backup"

# Append a deliberately broken import to the top of the file. Use a
# named export that demonstrably does not exist in any module under
# `@/components/ui/...`. tsc must surface TS2305 (or similar).
{
  printf '%s\n' 'import { NonexistentSymbolForGateTest } from "@/components/ui/select";'
  printf '%s\n' 'void NonexistentSymbolForGateTest;'
  cat "$backup"
} > "$target"

set +e
npm run --silent typecheck > /tmp/verify-typecheck-gate.log 2>&1
exit_code=$?
set -e

if [[ $exit_code -eq 0 ]]; then
  echo "verify-typecheck-gate: FAIL — the typecheck gate accepted obviously broken code." >&2
  echo "verify-typecheck-gate: tsc must be invoked with -p tsconfig.app.json (or -b)," >&2
  echo "verify-typecheck-gate: not the bare root tsconfig.json (which has files: [] → no-op)." >&2
  exit 1
fi

# Confirm the specific failure mode rather than catching, e.g., a stray
# syntax error from the injection harness.
if ! grep -q "NonexistentSymbolForGateTest" /tmp/verify-typecheck-gate.log; then
  echo "verify-typecheck-gate: typecheck failed but not on the injected symbol." >&2
  echo "verify-typecheck-gate: dumping log:" >&2
  cat /tmp/verify-typecheck-gate.log >&2
  exit 1
fi

echo "verify-typecheck-gate: ok — gate refused the broken import."
