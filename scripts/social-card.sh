#!/usr/bin/env bash
# Regenerate static/social-card.png (the Open Graph share image, 1200x630) from
# static/social-card.svg. Edit the SVG, run this, commit both.
#   ./scripts/social-card.sh
#
# No Rust dependency and nothing to install on macOS: the first renderer found
# is used, in this order —
#   rsvg-convert  (librsvg; `brew install librsvg` / apt `librsvg2-bin`)
#   sips          (built into macOS; rendered the committed PNG)
#   Google Chrome (headless screenshot of the SVG at exactly 1200x630)
# The SVG uses the app's serif stack (Charter first) and fetches no font, so
# each renderer draws the type with whichever system face it has; a PNG made
# on another machine can differ by a few pixels of hinting, never in layout.
# The HTML advertises 1200x630 and a test checks the PNG's own header, so the
# output is verified below before it replaces anything.
set -euo pipefail
cd "$(dirname "$0")/.."

src=static/social-card.svg
out=static/social-card.png
tmp="$(mktemp -t social-card).png"
trap 'rm -f "$tmp"' EXIT

chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if command -v rsvg-convert >/dev/null 2>&1; then
  echo "== rsvg-convert =="
  rsvg-convert --width 1200 --height 630 --format png --output "$tmp" "$src"
elif command -v sips >/dev/null 2>&1; then
  echo "== sips =="
  sips -s format png "$src" --out "$tmp" >/dev/null
elif [ -x "$chrome" ] || command -v google-chrome >/dev/null 2>&1; then
  echo "== headless chrome =="
  [ -x "$chrome" ] || chrome="$(command -v google-chrome)"
  "$chrome" --headless=new --disable-gpu --hide-scrollbars --window-size=1200,630 \
    --screenshot="$tmp" "file://$PWD/$src" 2>/dev/null
else
  echo "no SVG renderer found (rsvg-convert, sips or Google Chrome)" >&2
  exit 1
fi

# The PNG header must say 1200x630 (IHDR width/height at offsets 16 and 20).
read -r w h < <(od -An -tu4 --endian=big -j16 -N8 "$tmp" 2>/dev/null \
  || python3 -c 'import struct,sys; b=open(sys.argv[1],"rb").read(24); print(*struct.unpack(">II", b[16:24]))' "$tmp")
if [ "$w" != 1200 ] || [ "$h" != 630 ]; then
  echo "rendered ${w}x${h}, expected 1200x630" >&2
  exit 1
fi
size=$(wc -c <"$tmp" | tr -d ' ')
if [ "$size" -gt 1000000 ]; then
  echo "rendered ${size} bytes; card fetchers reject images over 1 MB" >&2
  exit 1
fi

mv "$tmp" "$out"
echo "wrote $out (${w}x${h}, ${size} bytes)"
