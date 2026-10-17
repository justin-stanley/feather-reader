#!/usr/bin/env bash
# Pins scripts/release-notes.sh: the section it extracts, the anchor it links,
# and its refusals. Run by CI (`release notes` job).
set -euo pipefail
cd "$(dirname "$0")/.."
notes=scripts/release-notes.sh
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "$tmp/CHANGELOG.md" <<'MD'
# Changelog

## Unreleased

- not yet released

## 0.4.10 — 2026-10-17

Summary line.

### Fixed

- **A fix.**


## 0.4.1 — 2026-10-04

Older.

## 0.4.0 — 2026-10-03

## 0.3.9 — 2026-10-02
MD

out="$("$notes" 0.4.10 "$tmp/CHANGELOG.md")"
expected='Summary line.

### Fixed

- **A fix.**

Full engineering detail: [CHANGELOG.md](https://github.com/justin-stanley/feather-reader/blob/v0.4.10/CHANGELOG.md#0410--2026-10-17).'
[ "$out" = "$expected" ] || fail "0.4.10 notes differ:
$out"

# 0.4.1 is a prefix of 0.4.10: it must get its own section, not 0.4.10's.
out="$("$notes" 0.4.1 "$tmp/CHANGELOG.md")"
case "$out" in
  Older.*"#041--2026-10-04)."*) ;;
  *) fail "0.4.1 took the wrong section: $out" ;;
esac

# Refusals print nothing on stdout and exit non-zero.
for args in "0.4.0" "9.9.9" "v0.4.10" "0.4.10-rc.1"; do
  if out="$("$notes" $args "$tmp/CHANGELOG.md" 2>/dev/null)"; then
    fail "$args should be refused"
  fi
  [ -z "$out" ] || fail "$args printed notes while refusing: $out"
done

# The real CHANGELOG has a section for the version Cargo.toml carries, so a
# final tag of this commit can always be released.
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)"
"$notes" "$version" >/dev/null || fail "CHANGELOG.md has no usable $version section"

echo "release-notes.sh: ok ($version)"
