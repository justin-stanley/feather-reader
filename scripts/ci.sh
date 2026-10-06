#!/usr/bin/env bash
# Local CI — runs the same checks as .github/workflows/ci.yml, in your own environment.
# Free-tier-friendly: zero GitHub-hosted Actions minutes. Run before you push.
#   ./scripts/ci.sh
# (Enable as a pre-push gate: `git config core.hooksPath .githooks`.)
set -euo pipefail
cd "$(dirname "$0")/.."

# Bring cargo onto PATH if rustup installed it under ~/.cargo.
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

echo "== rustfmt =="
cargo fmt --all --check
echo "== build =="
cargo build --all-targets --locked
echo "== test =="
cargo test --locked
echo "== clippy (-D warnings) =="
cargo clippy --all-targets -- -D warnings

if command -v sqlite3 >/dev/null 2>&1; then
  echo "== teardown script =="
  bash scripts/test-teardown.sh
else
  echo "== teardown script: skipped (no sqlite3) =="
fi

if [ -d oauth-sidecar ] && command -v npm >/dev/null 2>&1; then
  echo "== oauth-sidecar (npm ci + build + typecheck) =="
  ( cd oauth-sidecar && npm ci && npm run build && npm run typecheck )
else
  echo "== oauth-sidecar: skipped (no npm / no sidecar) =="
fi

echo ""
echo "ALL CI CHECKS PASSED (local)"
