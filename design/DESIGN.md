# FeatherReader — Design System

> **read, quietly.** This document is the design authority for FeatherReader's UI.
> The living prototype is in [`mockups/`](./mockups/) — real HTML + one CSS file,
> directly liftable into the askama templates. Rendered reference images are in
> [`screenshots/`](./screenshots/).

---

## 1. Identity & mood

FeatherReader is a **calm, typography-first reader for people who left algorithmic
feeds on purpose**. The visual language follows the product thesis: attention is the
scarce resource, so the interface must cost as little of it as possible.

- **Feather** — light, airy, unhurried. Generous whitespace, hairline borders,
  whisper-quiet shadows. Nothing blinks, bounces, or badges for attention.
- **Paper & ink** — warm off-white paper, warm near-black ink. Editorial, not
  clinical; restful, not brutalist. A serif carries every word the user came to
  read; a system UI face carries the chrome and stays out of the way.
- **One accent** — a single muted **spruce** green for everything interactive:
  links, unread marks, primary buttons, focus rings, selection. The lone exception
  is **starred** (a muted gold), because "kept" deserves its own warmth.
- **Quietly principled** — the atproto story ("your subscriptions live in *your*
  PDS") is surfaced in copy at exactly two moments: sign-in and subscribe. It is a
  promise, not a banner.

Anti-goals: dashboards, density toggles, colored feed icons, unread-count anxiety
mechanics, decorative illustration, webfonts.

---

## 2. Design tokens

All tokens are CSS custom properties on `:root` in
[`mockups/feather.css`](./mockups/feather.css) — copy that block verbatim into the
real stylesheet. No build step, no preprocessor.

### 2.1 Color

Light is the default; dark ships as a first-class equal via
`@media (prefers-color-scheme: dark)` **and** a forced `html[data-theme="dark|light"]`
override (for the manual toggle the product spec promises, and for deterministic
screenshots). `color-scheme: light dark` is declared so form controls and scrollbars
follow.

| Token | Light | Dark | Role |
|---|---|---|---|
| `--bg` | `#faf8f3` | `#191714` | paper / page |
| `--surface` | `#ffffff` | `#211e1a` | cards, inputs, hovered rows |
| `--surface-2` | `#f3f0e8` | `#14120f` | rail, wells, code blocks |
| `--ink` | `#2a2723` | `#ede8dd` | primary text |
| `--ink-soft` | `#5c564b` | `#bab2a3` | secondary text, snippets |
| `--muted` | `#6f6959` | `#9c947f` | metadata, timestamps |
| `--line` | `#e8e3d7` | `#35312a` | hairlines |
| `--line-soft` | `#f0ece2` | `#2a2721` | subtler hairlines |
| `--accent` | `#3e6459` | `#93bfb2` | spruce — links, unread, primary actions |
| `--accent-deep` | `#395d53` | `#a8cdc1` | hover/active |
| `--accent-soft` | `#e9efec` | `#24312c` | selected wash, badges |
| `--on-accent` | `#ffffff` | `#14211d` | text on accent |
| `--star` | `#8a6a14` | `#d2ac4b` | starred (the only second hue) |
| `--danger` | `#9d3b2d` | `#d98374` | destructive affordances |
| `--scrim` | `rgba(31,27,20,.4)` | `rgba(0,0,0,.55)` | drawer/overlay backdrop |

**Measured contrast (WCAG):** ink/paper 14.0 · ink-soft/paper 6.9 · muted/paper 5.2 ·
accent/paper 6.2 · white/accent 6.6 · star/paper 4.8 — and 5.9–14.6 for the dark
equivalents. Every text pairing is AA at body size; most are AAA. Keep it that way:
never introduce a text color lighter than `--muted`.

### 2.2 Type

System stacks only — instant paint, zero network, zero licensing, matches the
single-binary ethos:

```css
--font-serif: "Charter", "Iowan Old Style", "Palatino Linotype", Palatino,
              Georgia, "Times New Roman", serif;   /* reading */
--font-ui:    system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue",
              Arial, sans-serif;                    /* chrome  */
--font-mono:  ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas,
              "Liberation Mono", monospace;         /* code, feed URLs, kbd */
```

**Where each face goes:** serif = article body (`.prose`), article titles, entry
titles, empty-state headings, the wordmark on sign-in. UI = everything else. The
serif is the voice of the *content*; the sans is the voice of the *app*.

Scale (~1.19 ratio, deliberately tight):

| Token | Size | Use |
|---|---|---|
| `--text-xs` | 12px | fine print, kbd, folder labels |
| `--text-sm` | 13px | metadata, counts, hints |
| `--text-base` | 15px | UI chrome, buttons, nav |
| `--text-md` | 17px | entry titles, reading size (mobile) |
| `--text-lg` | 20px | section headings |
| `--text-xl` | 25px | article title (mobile), sign-in wordmark |
| `--text-2xl` | 31px | article title (≥700px) |

Reading: `--measure: 66ch`, `--reading-leading: 1.72`, `--reading-size` = 17px on
mobile → 18px at ≥900px. These three tokens **are the product**; change nothing here
casually.

### 2.3 Spacing, shape, elevation, motion

- **Spacing** — 4px base: `--s1..--s8` = 4, 8, 12, 16, 24, 32, 48, 64. Whitespace is
  the primary grouping device; hairlines are the fallback, boxes the last resort.
- **Radii** — `--r-sm 6px` (kbd, chips), `--r-md 10px` (buttons, inputs, rows),
  `--r-lg 16px` (cards, overlay), `--r-full` (pills, avatar).
- **Shadows** — two levels only. `--shadow-1` (resting cards) is nearly subliminal;
  `--shadow-2` (drawer, overlay, floating action pill) is the maximum drama allowed.
- **Motion** — `--ease: cubic-bezier(.2,.7,.3,1)`; `--dur-1: 120ms` for state flips
  (hover, read-dim), `--dur-2: 220ms` for movement (drawer, overlay). Nothing else
  animates. A global `prefers-reduced-motion` block zeroes all of it.
- **Touch** — `--tap: 44px` minimum target on every interactive element; inputs use
  `font-size: 1rem` (≥16px) to prevent iOS zoom-on-focus.

---

## 3. Responsive strategy — mobile-first

Base styles target a **390px phone**. Three `min-width` breakpoints enhance upward;
never the reverse.

| Breakpoint | Shape |
|---|---|
| base (<700px) | Single column. Sticky blurred **topbar** (56px): menu / title+count / mark-all-read. The rail is an **off-canvas drawer** (`transform`, `visibility`, scrim; ≤85vw). Reader actions are a **bottom-fixed action bar** in thumb reach, with `env(safe-area-inset-bottom)`. |
| ≥700px | More air: larger article title (`--text-2xl`), wider row padding. |
| ≥900px | The desktop shape. `grid: 280px rail + fluid content`. Topbar disappears; the rail is **persistent + sticky** with the identity chip pinned at the bottom and the `?`-hint visible (keyboard is a desktop affordance). The reader action bar becomes a **floating pill**, bottom-center of the reading column. Reading size steps up to 18px. j/k cursor styling activates here. |
| ≥1200px | Gutters only: content column widens 46rem → 48rem. |

The mobile drawer and desktop rail are the **same DOM element** (`.rail`) — no
duplicated nav to keep in sync, and htmx can update unread counts in one place.

---

## 4. Components

Every component below exists in the mockups; class names are the spec.

### 4.1 App shell (`.shell`, `.topbar`, `.rail`, `.scrim`)
- `.rail` contains, top-to-bottom: brand → filter → folders/feeds (scrollable
  middle) → "Manage feeds" tool → kbd hint → identity chip. Brand mark is an inline
  feather SVG in `currentColor` accent — no image asset.
- **Filter** (`.filter`): a 3-segment control — All / Unread / Starred. These are
  *links* (server-rendered views), current one marked `aria-current="page"` and
  lifted with `--surface` + `--shadow-1`.
- **Feeds** (`.feed-link`): 44px rows; unread feeds get medium-weight ink names and
  an accent-colored tabular-nums count (plain text, never a pill). Feeds with 0
  unread show no number at all — silence over zero.
- **Folders** (`.folder-name`): 12px uppercase muted labels. Ungrouped feeds sit
  under a plain "Feeds" label.
- **Identity chip** (`.identity`): initials avatar (accent circle), `@handle`,
  the one-line reminder *"your feeds live in your PDS"*, quiet Sign out.
- Drawer state = `.rail-open` on `.shell`, toggled by `keyboard.js` (5 lines);
  `aria-expanded` mirrors it. Scrim click and `Esc` close it.

### 4.2 Article list (`.entry-list`, `.entry`)
- A row is: **7px accent unread dot** (absolutely placed, fades out when read) →
  serif title → 2-line clamped sans snippet → meta line (`feed · relative-time`,
  with a real `<time datetime>`), plus a 44px **star button** on the right.
- The whole text block is one `<a>` — one big target. The star is a sibling
  `<button aria-pressed>` so the row stays a valid link and htmx can swap the
  button alone.
- **Read treatment**: title and snippet drop to `--muted`, weight 500, dot fades —
  read rows *recede* but remain scannable. No strikethrough, no hiding.
- **Cursor** (`.is-cursor`, ≥900px only): `--accent-soft` wash + 2px accent left
  edge. Moved by j/k, used by o/m/s.
- List width caps at 46rem (48rem ≥1200px), centered — list rows deserve a measure
  too.

### 4.3 Reader view (`.article`, `.prose`, `.actionbar`)
- Header: eyebrow (`accent feed name · date`) → serif title (`text-wrap: balance`)
  → byline (read time · source link). A hairline separates header from body.
- `.prose` wraps **ammonia-sanitized foreign HTML** — style defensively: everything
  capped to `--measure`, `overflow-wrap: break-word`, images centered + rounded,
  `pre` scrolls horizontally, tables get the UI face at 13px, iframes capped.
  Blockquotes: 3px accent left border, italic, soft ink. Links: underlined with a
  45%-alpha accent underline that saturates on hover (underlines are load-bearing
  inside body text; chrome links stay underline-free).
- **Action bar**: prev / mark-read / star / open-original / next as five 44px icon
  buttons. Mobile: full-width fixed bottom, blurred surface. Desktop: floating
  pill (`border-radius: full`, `--shadow-2`) bottom-center of the column, offset by
  the rail width. Toggle state via `aria-pressed` — read check turns accent,
  star fills gold (`.actionbar-read` / `.actionbar-star`).

### 4.4 Actions & states
- **Empty** (`.empty`): centered feather glyph, serif "All caught up",
  *"Nothing unread. The quiet is the point."* No confetti. Ever.
- **Loading**: htmx-native — `.htmx-indicator` + `.spinner` (a 1em border spinner)
  inside the triggering button; `.skeleton` rows (pulsing `.bone` bars) for initial
  list loads. htmx's `.htmx-added` gives swapped-in rows a brief accent-soft wash
  that fades over 600ms.
- **Flash** (`.flash`, `.flash.error`): a single quiet strip above the list,
  `role="status"` / `role="alert"`.
- **Shortcuts overlay** (`.kbd-overlay`): scrim + card, `role="dialog"
  aria-modal`, opened with `?`, closed by Esc / scrim / button. `<kbd>` styling has
  a 2px bottom border — the only skeuomorphism in the app.
- **keyboard.js** (~90 lines, progressive enhancement only): drawer toggle, overlay,
  and j/k/o/m/s/A. Ignores keystrokes in form fields and with modifiers. In the
  real app, m/s/A trigger the htmx endpoints (`htmx.trigger(...)` or `.click()` on
  the row's existing controls) instead of toggling classes.

### 4.5 Feed management (`.manage`)
- **Add**: URL input + primary "Find" (htmx → discovery). Hint: *"A site URL works
  too."* The **discovered card** shows an RSS glyph, title, canonical feed URL
  (mono), a folder `<select>`, primary "Subscribe" — and the PDS note: *"Saved to
  **your PDS** as a `community.lexicon.rss.subscription` record — portable to any
  reader."* This is one of the two places the architecture speaks.
- **Your feeds**: folder sections (`.manage-folder`) with Rename / Delete-folder
  quiet buttons; feed rows (`.manage-row`) with title + mono URL, Rename +
  Unsubscribe (danger-on-hover quiet button; htmx `hx-delete` removes the row).
- **OPML**: Import (file picker) + Export as plain `.btn`s, with the promise
  spelled out: *"Export is always available — leaving must be as easy as
  arriving."*

### 4.6 Auth (`.auth`)
- A single centered card on bare paper: feather mark (48px, accent) → serif
  **FeatherReader** → *read, quietly* → labeled handle input
  (`autocapitalize=none autocorrect=off`, `autocomplete=username`) → primary
  **Continue**.
- Below a hairline, the pitch in 4 lines: no signup / no password / OAuth happens
  on *your* server / records are portable via `community.lexicon.rss.*`.
- Footer: `Open source · AGPL-3.0 · self-hostable`. That's the whole page; trust
  through restraint.

---

## 5. Accessibility

- **Contrast**: all text pairings AA+ (measured, §2.1). Non-text indicators (unread
  dot, star fill, focus ring) exceed 3:1 against their backgrounds.
- **Focus**: global `:focus-visible` — 2px accent outline, 2px offset. Never
  removed, never restyled per-component. Inputs swap their border for the ring.
- **Semantics**: skip-link first in DOM; `nav`/`main`/`article`/`time[datetime]`;
  filter and current feed use `aria-current="page"`; toggles use `aria-pressed`;
  drawer button `aria-expanded` + `aria-controls`; overlay is a labelled modal
  dialog; icon-only buttons always carry `aria-label` (with the shortcut key
  noted, e.g. "Star entry (s)"); decorative SVGs `aria-hidden`.
- **Motion**: everything honors `prefers-reduced-motion: reduce`.
- **No-JS**: every action is a real link or form; keyboard.js and htmx are
  strictly additive.

---

## 6. Implementer handoff — mapping onto askama + htmx

The mockups intentionally mirror the existing template structure
(`base.html` / `index.html` / `entry_row.html` / `entry.html` / `login.html`):

1. **CSS**: replace `static/style.css` with `design/mockups/feather.css` wholesale
   (it subsumes the current token sketch — same spirit, more surface). Drop
   `design/mockups/keyboard.js` in as `static/keyboard.js`. Remove the mockup-only
   block marked *"Mockup-only"* (the `html[data-state]` rules) if unwanted.
2. **`base.html`**: adopt the mockup shell — skip-link, `.topbar` (mobile),
   `.scrim`, `.rail` (the current sidebar content moves in here), `.content` as the
   `{% block %}` target. Keep `data-theme` on `<html>`; server renders
   `auto|light|dark` — `feather.css` already honors it. The head inline-script in
   the mockups is screenshot plumbing; the real app sets `data-theme` server-side.
3. **`entry_row.html`** → `.entry` markup from `list.html`: swap the current
   text "Mark read" form for the star button + unread-dot treatment; keep
   `hx-target="#entry-{id}" hx-swap="outerHTML"` exactly as today. Server should
   emit relative times (`2h`, `1d`) into `<time datetime="…">`.
4. **`entry.html`** → `article.html` structure from `reader.html`: wrap the
   sanitized `content_html` in `<div class="prose">`; the footer form becomes the
   `.actionbar` (five buttons; next/prev are plain links the server computes).
5. **`index.html` sidebar forms** (subscribe + OPML) move to the **Manage feeds**
   page (`add-feed.html` structure); the rail keeps only navigation. Discovery
   (`hx-post`→ discovered card) matches §4.5.
6. **`login.html`** → `signin.html` structure; the existing OAuth copy shortens to
   the `.auth-why` paragraph.
7. **Filters** (All/Unread/Starred) are routes (`/`, `/?filter=all`, `/starred`
   or similar) rendering the same list template — the segmented control is links,
   not client state.
8. **Unread counts** in the rail: wrap the rail in an htmx OOB target (or
   `hx-swap-oob` on a `.feed-count` span) so mark-read swaps can update counts
   without a full reload — the single-`.rail` design makes this one target.

Sample-content note: the mockups use real-looking feeds/titles as placeholder
content only; nothing in them is a claim about real posts.

---

## 7. Prototype & screenshots

- `mockups/list.html` — shell + article list (+ `?state=empty`, `?overlay=1`)
- `mockups/reader.html` — reader view + action bar
- `mockups/add-feed.html` — feed management + OPML
- `mockups/signin.html` — auth
- `mockups/feather.css` — the entire design system (tokens → components)
- `mockups/keyboard.js` — drawer + shortcuts (progressive enhancement)

All pages accept `?theme=light|dark` for deterministic theming. `screenshots/`
holds 18 rendered PNGs: the four views × {mobile 390×844, desktop 1280×900} ×
{light, dark}, plus the empty state and the shortcuts overlay.

Regenerate (headless Chrome; macOS clamps windows to ≥500px wide, hence the
iframe harness for mobile):

```sh
# desktop
chrome --headless --disable-gpu --hide-scrollbars --window-size=1280,900 \
  --screenshot=design/screenshots/list-desktop-dark.png \
  "file://$PWD/design/mockups/list.html?theme=dark"
# mobile: wrap the page in a centered 390×844 iframe inside a 600×844 window,
# screenshot, then center-crop to 390×844 (see git history for the harness).
```
