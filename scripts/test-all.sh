#!/usr/bin/env bash
# Unit tests for every implementation. Each runs the shared vectors in
# spec/test-vectors. Output is kept, so a failure says what failed, and the script
# stops at the first one. The real-process scripts (cli-flows.sh, demo.sh,
# oidc-demo.sh, policy-dag-demo.sh) are separate: they take minutes and need ports.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== rust"
cargo test --workspace --locked

echo "== js"
(
  cd packages/js
  # Install exactly what the lockfile says, but only when it is not already there.
  npm ls --all >/dev/null 2>&1 || npm ci --no-audit --no-fund
  npm test
  npx tsc --noEmit
)

echo "== python"
(
  cd packages/python
  uv sync --frozen --quiet
  uv run pytest -q
)
