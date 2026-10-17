#!/usr/bin/env bash
# Print the GitHub release notes for VERSION (e.g. 0.4.10) on stdout: its
# CHANGELOG.md section, without the heading, then a link to that section at
# the tag. Fails, printing nothing, when CHANGELOG.md has no "## VERSION — "
# heading or the section is empty, so a release is never created with blank
# or wrong notes.
#
#   scripts/release-notes.sh 0.4.10 [CHANGELOG.md]
set -euo pipefail

version="${1:?usage: release-notes.sh VERSION [CHANGELOG]}"
changelog="${2:-CHANGELOG.md}"
case "$version" in
  v*) echo "release-notes.sh: pass the version without its v ($version)" >&2; exit 2 ;;
  *-*) echo "release-notes.sh: $version is a pre-release; rcs have no CHANGELOG section" >&2; exit 2 ;;
esac

heading="$(awk -v p="## $version — " 'index($0, p) == 1 { print; exit }' "$changelog")"
case "$heading" in
  "## $version — "*) ;;
  *) echo "release-notes.sh: no '## $version — ' heading in $changelog" >&2; exit 1 ;;
esac

# The section: every line after the heading up to the next "## " heading,
# with leading and trailing blank lines dropped.
body="$(awk -v h="$heading" '
  $0 == h { on = 1; next }
  on && /^## / { exit }
  on { print }
' "$changelog" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')"

# **Unwrap hard-wrapped lines.** GitHub renders a release body with every
# single newline as a line break, unlike a Markdown file, so the CHANGELOG's
# 80-column wrapping showed as ragged lines (v0.4.9). Each paragraph and list
# item becomes one line. A heading (`#`s then a space; `#246` at the start of
# a wrapped line is text), a blank line, a rule or setext underline, a list marker, a quote or
# a table row starts a new line, a hard break (two trailing spaces or a
# backslash) is kept, and a fenced code block passes through as is.
body="$(printf '%s\n' "$body" | awk '
  function flush() { if (buf != "") { print buf; buf = "" } }
  {
    stripped = $0
    sub(/^[ \t]+/, "", stripped)
    if (stripped ~ /^(```|~~~)/) { flush(); print; fence = !fence; next }
    if (fence) { print; next }
    if (stripped == "") { flush(); print ""; next }
    if (stripped ~ /^#+( |$)/) { flush(); print; next }
    # A rule or a setext underline (`---`, `***`, `___`, `===`) keeps its
    # own line, so it still underlines or follows the paragraph above.
    if (stripped ~ /^(---+|\*\*\*+|___+|=+)[ \t]*$/) { flush(); print; next }
    # A deliberate hard break (two trailing spaces, or a backslash) ends the
    # line it is on: joining would drop it, or leave a stray backslash.
    if (buf == "" || buf ~ /(  |\\)$/ || stripped ~ /^([-*+] |[0-9]+[.)] |>|\|)/) { flush(); buf = $0; next }
    buf = buf " " stripped
  }
  END { flush() }
')"
if [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
  echo "release-notes.sh: the $version section of $changelog is empty" >&2
  exit 1
fi

# GitHub's heading anchor: lowercase, drop everything but letters, digits,
# spaces and hyphens (the dots and the em dash), spaces become hyphens.
# "0.4.10 — 2026-10-17" -> "0410--2026-10-17".
anchor="$(printf '%s' "${heading#\#\# }" | LC_ALL=C tr '[:upper:]' '[:lower:]' \
  | LC_ALL=C sed -e 's/[^a-z0-9 -]//g' -e 's/ /-/g')"

printf '%s\n\n' "$body"
printf 'Full engineering detail: [CHANGELOG.md](https://github.com/justin-stanley/feather-reader/blob/v%s/CHANGELOG.md#%s).\n' \
  "$version" "$anchor"
