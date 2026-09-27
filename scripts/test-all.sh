#!/usr/bin/env bash
# Unit tests for every implementation (each runs spec/test-vectors/authz.json).
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== rust";   cargo test -q --workspace 2>&1 | grep -E "test result|FAILED|panicked" | grep -v " 0 passed"
echo "== js";     (cd packages/js && npm install --silent >/dev/null && npm test 2>&1 | grep -E "^ℹ (pass|fail)" && npx tsc --noEmit)
echo "== python"; (cd packages/python && uv sync -q && uv run pytest -q 2>&1 | tail -1)
