# Handoff: personal site — Jekyll static blog ("Buffer, quiet")

## Overview

Build a static personal website: a short intro/about, a technical blog (CTF write-ups, vulnerability research, philosophy), and a set of short cheatsheets. Jekyll, mostly static, no server-side anything. Deployable to GitHub Pages / Netlify / Cloudflare Pages.

The visual concept is **a neovim buffer that has been calmed down**: Solarized colors, JetBrains Mono Nerd Font throughout, a line-number gutter, a colored mode statusline, and a `:` command palette instead of a conventional nav bar. Desktop keeps the editor chrome; mobile drops the parts that don't earn their pixels.

## About the design files

`Personal Site Mockups.dc.html` in this bundle is a **design reference created in HTML** — a prototype showing intended look and structure, not production code to copy. Open it in a browser (needs network for the Google Fonts link) and scroll: it is organized as three "turns" of options, newest at top.

**Build these two, and ignore the rest:**

| Option id | What it is | Use it for |
|---|---|---|
| `2a` | Desktop: welcome, about with `:` palette open, post with inline figure | all viewports ≥ 900px |
| `2c` | Four screenshot/figure treatments + zoom lightbox | image handling everywhere |
| `3b` | Mobile: home, palette sheet, post with figure | viewports < 900px |

Turn 1 (`1a`/`1b`/`1c`) and `3a` are rejected explorations. Do not build them. `1b` shows a Solarized **Light** treatment — useful as reference for the light theme, which is a required toggle (see Theming).

## Fidelity

**High-fidelity.** Colors, type sizes, and spacing in this document are final; match them. Where the mockup and this document disagree, this document wins (the mockup frames are fixed-size and slightly compressed).

Content in the mockups is placeholder — name "a. hartmann", handle, post titles, `team::nullbyte`, the stack-pivoting article. Replace with the site owner's real content; keep the *shape* of the copy (short subtitle line, `focus`/`team` key-value rows, TL;DR blocks).

---

## Design tokens

### Color — Solarized (Ethan Schoonover), exact values

```scss
// _sass/_tokens.scss
$base03:  #002b36;  $base02:  #073642;  $base01:  #586e75;  $base00: #657b83;
$base0:   #839496;  $base1:   #93a1a1;  $base2:   #eee8d5;  $base3:  #fdf6e3;
$yellow:  #b58900;  $orange:  #cb4b16;  $red:     #dc322f;  $magenta:#d33682;
$violet:  #6c71c4;  $blue:    #268bd2;  $cyan:    #2aa198;  $green:  #859900;

// two non-Solarized utility shades used by the mockups, keep them:
$sunk:    #00212a;  // panels/figures sunk below the dark bg
$gutter:  #0b3d49;  // gutter digits + inactive statusline cell on dark
```

Semantic mapping, as CSS custom properties on `:root` / `[data-theme]`:

| Token | Dark | Light |
|---|---|---|
| `--bg` | `#002b36` base03 | `#fdf6e3` base3 |
| `--bg-sunk` (figures, code, palette) | `#00212a` | `#eee8d5` base2 |
| `--bg-chrome` (statusline, tabline) | `#073642` base02 | `#eee8d5` base2 |
| `--rule` | `#073642` | `#e4dcc4` |
| `--fg-strong` (headings) | `#fdf6e3` base3 | `#073642` base02 |
| `--fg` (body) | `#93a1a1` base1 | `#586e75` base01 |
| `--fg-mid` (list titles) | `#eee8d5` base2 | `#073642` |
| `--fg-dim` (meta, captions) | `#586e75` base01 | `#93a1a1` base1 |
| `--fg-faint` (gutter digits) | `#0b3d49` | `#cfc7ae` |
| `--link` | `#268bd2` blue | `#268bd2` |
| `--link-hover` | `#cb4b16` orange | `#cb4b16` |

**Category accent colors** — one per category, used for the tag word, the post's statusline mode block, and figure/TL;DR left borders:

| Category | Slug | Color |
|---|---|---|
| Pwn / exploitation | `pwn` | `#b58900` yellow |
| Vulnerability research | `vr` | `#d33682` magenta |
| Cheatsheet | `cheat` | `#2aa198` cyan |
| Philosophy | `phil` | `#6c71c4` violet |
| Reversing | `rev` | `#268bd2` blue |

**Statusline mode-block color is the page-type signal** — do not make it uniform:
`home → $green`, `about/pages → $blue`, `post → the post's category color`, `command palette open → $blue`, `zoom/lightbox → $violet`.

### Typography

One family: **JetBrains Mono Nerd Font**, self-hosted (see Fonts). Weights 400 / 500 / 700, plus italic 400. `letter-spacing: -0.02em` on the big display sizes only; `letter-spacing: .06em–.14em` on uppercase micro-labels.

| Role | Desktop | Mobile | Weight | Color |
|---|---|---|---|---|
| Home name | 36px / 1.1 | 30px / 1.08 | 700 | `--fg-strong` |
| Home subtitle | 14px / 1.5 | 12.5px / 1.6 | 400 | `$cyan` |
| Post `h1` | 24–25px / 1.2 | 24px / 1.2 | 700 | `--fg-strong` |
| Post `h2` | 17px | 16px | 700 | `$yellow` |
| Body | 13.5px / 1.85 | 15px / 1.75 | 400 | `--fg` |
| Post-list title | 14.5px | 16px / 1.35 | 400 | `--fg-mid` |
| Meta / uppercase labels | 11px, `.05em` | 10.5px | 400 | `--fg-dim` |
| Code / pre | 12.5px / 1.8 | 11.5px / 1.7 | 400 | `--fg` |
| Statusline | 11.5px | 11.5px | 400 (mode block 700) | see above |
| Gutter digits | 11.5–12px / 2.05 | — | 400 | `--fg-faint` |
| Figure caption | 11.5px | 11px | 400 | `--fg-dim` |

Body measure caps at **50–52ch**. Never go below 12.5px on mobile body text.

### Spacing / geometry

4px base. Common values: gutter width `60px` (desktop, `54px` in post view), content padding `38px 44px` (home) / `24px 40px` (post), rule margins `24px 0`, statusline cell padding `7px 13px` desktop / `10px 13px` mobile (44px min touch target).

**Radii: 0 everywhere.** No rounded corners, no box-shadows — that flatness is the aesthetic. Only exceptions: the mobile palette sheet (`16px 16px 0 0`) and the sheet's drag handle (`2px`).

Borders are always `1px solid var(--rule)`; accent borders are `2px` on the **left** of figures/TL;DR blocks, or `2px` bottom on the active tabline item.

---

## Fonts

Self-host — do not use a CDN, and note that Google Fonts does **not** serve the Nerd Font patched build.

1. Download **JetBrainsMono Nerd Font** (`JetBrainsMono.zip`) from the nerd-fonts releases. License: OFL 1.1 — ship `LICENSE` alongside.
2. Convert/subset the four faces you need to `woff2`: Regular, Medium(500), Bold, Italic. Full Nerd Font files are large (~2–4MB each) because of the glyph patches; subset with `pyftsubset`, keeping Latin + the specific Nerd glyph codepoints you actually use, e.g.:

```bash
pyftsubset JetBrainsMonoNerdFont-Regular.ttf \
  --unicodes="U+0000-00FF,U+2010-2027,U+2190-21FF,U+2500-257F,U+25A0-25FF,U+E0A0-E0A3,U+E0B0-E0B3,U+F015,U+F07B,U+F07C,U+F0F6,U+F121,U+F09B,U+F1D3,U+F02D" \
  --flavor=woff2 --layout-features='*' \
  --output-file=assets/fonts/jbmono-nf-400.woff2
```

3. `@font-face` with `font-display: swap`, `unicode-range` omitted, and a stack of `"JetBrains Mono NF", ui-monospace, SFMono-Regular, Menlo, monospace`.
4. Nerd glyphs used in the design (icons are the only place they appear — keep it restrained): powerline separators `U+E0B0/E0B2` in the statusline, `` for github, `` for RSS, `` for file/folder in the cheatsheet index. Every glyph gets `aria-hidden="true"` and a text label next to it. **Never** encode meaning in a glyph alone.

Budget check: total font payload should stay under ~250KB. If it doesn't, drop the Medium face and use 400/700 only.

---

## Repository structure

```
.
├── _config.yml
├── Gemfile
├── _data/
│   ├── categories.yml        # slug → label + hex, single source of truth
│   └── commands.yml          # : palette entries
├── _includes/
│   ├── head.html
│   ├── gutter.html           # renders N line numbers
│   ├── statusline.html       # mode block + file + right cells
│   ├── tabline.html          # desktop only
│   ├── palette.html          # : command palette (desktop overlay + mobile sheet)
│   ├── figure.html           # image treatments ①②③
│   ├── attachments.html      # treatment ④
│   ├── postmeta.html
│   └── postlist.html
├── _layouts/
│   ├── default.html
│   ├── home.html
│   ├── page.html
│   ├── post.html
│   └── cheatsheet.html
├── _posts/
│   └── 2026-08-14-stack-pivoting-past-a-24-byte-overflow.md
├── _cheatsheets/             # collection
│   └── pwndbg-keys.md
├── _sass/
│   ├── _tokens.scss  _base.scss  _chrome.scss  _home.scss
│   ├── _post.scss  _figure.scss  _palette.scss  _rouge-solarized.scss
├── assets/
│   ├── css/main.scss         # front-matter dashes + @use of _sass
│   ├── js/{palette,lightbox,theme,progress}.js
│   ├── fonts/*.woff2
│   └── img/posts/<slug>/*.png
├── about.md
├── cheatsheets.md            # index of the collection
├── tags.md
└── 404.html
```

### Gemfile

```ruby
source "https://rubygems.org"
gem "jekyll", "~> 4.3"
group :jekyll_plugins do
  gem "jekyll-feed"        # /feed.xml
  gem "jekyll-seo-tag"
  gem "jekyll-sitemap"
  gem "jekyll-paginate-v2" # only if the post list outgrows one page
end
```

### _config.yml

```yaml
title: "a. hartmann"                    # replace
tagline: "vulnerability research · ctf · embedded network stacks"
url: "https://example.com"
baseurl: ""

markdown: kramdown
kramdown:
  input: GFM
  syntax_highlighter: rouge
  syntax_highlighter_opts:
    css_class: highlight
    span: { line_numbers: false }
    block: { line_numbers: false }

sass:
  style: compressed

collections:
  cheatsheets:
    output: true
    permalink: /cheatsheets/:name/

defaults:
  - scope: { path: "", type: posts }
    values: { layout: post, mode: NORMAL }
  - scope: { path: "", type: cheatsheets }
    values: { layout: cheatsheet, category: cheat }
  - scope: { path: "" }
    values: { layout: page }

permalink: /posts/:year/:title/
excerpt_separator: "<!--more-->"
plugins: [jekyll-feed, jekyll-seo-tag, jekyll-sitemap]
exclude: [Gemfile, Gemfile.lock, README.md, node_modules, vendor]
```

### _data/categories.yml

```yaml
pwn:   { label: "pwn",   long: "Exploitation",              color: "#b58900" }
vr:    { label: "vr",    long: "Vulnerability research",    color: "#d33682" }
cheat: { label: "cheat", long: "Cheatsheet",                color: "#2aa198" }
phil:  { label: "phil",  long: "Philosophy",                color: "#6c71c4" }
rev:   { label: "rev",   long: "Reversing",                 color: "#268bd2" }
```

### Post front matter contract

```yaml
---
title: "Stack pivoting past a 24-byte overflow"
date: 2026-08-14
category: pwn                 # must be a key in _data/categories.yml
tags: [glibc, rop]            # free-form, rendered dim after the category
subtitle: "Not enough room for a chain — so borrow someone else's stack."
env: "x86-64 / glibc 2.39"    # optional, appended to the meta line
tldr: "Control RBP and the function's own epilogue becomes your pivot gadget."
toc: true                     # desktop sidebar contents
attachments:                  # optional, renders treatment ④
  - { src: exploit-run.png,  alt: "exploit succeeding", caption: "exploit-run.png" }
---
```

Reading time: compute in Liquid, don't add a plugin — `{% assign words = content | number_of_words %}{{ words | divided_by: 200 | plus: 1 }} min`.

---

## Screens

### 1. Home — `_layouts/home.html`, option `2a` card 1 / `3b` card 1

**Purpose:** say who this is in one line, then get out of the way and list posts.

Desktop layout: full-height flex column. `[ gutter 60px | content ] + statusline`. Content padding `38px 44px 0 18px`.

- Name, 36px/700, `--fg-strong`.
- Subtitle, 14px, `$cyan`, 9px below.
- 1px `--rule`, margins `26px 0 20px`.
- Post list: `display:flex; flex-direction:column; gap:14px`. Each row is `display:flex; gap:18px; align-items:baseline` with three cells: date (11px, `--fg-dim`, `width:74px; flex:none`), category label (11px, category color, `width:34px; flex:none`), title (14.5px, `--fg-mid`). Whole row is the link; hover sets title → `--fg-strong` and shows a `$green` `▸` in the gutter position. No underline.
- Footer line: `37 posts · all · tags · rss`, 12px, `--fg-dim`, links `$blue`.
- Gutter renders exactly as many digits as fit the viewport height; highlight the digit adjacent to the currently hovered/focused row in `$yellow`.

Mobile (`3b`): no gutter, no tabline. Padding `26px 20px 0`. Name breaks onto two lines at 30px. Post rows lose the columns — meta line above the title: `PWN · 2026-08-14 · 11 MIN` (10.5px, category color on the category word, rest `--fg-dim`), title 16px/1.35 `--fg-mid`, `gap:22px` between entries.

### 2. About — `_layouts/page.html`, option `2a` card 2

Same chrome, mode block `$blue`. Content: `ABOUT` micro-label (11px, `$yellow`, `.14em`), `h1` 26px/700, two body paragraphs at 13.5px/1.85 capped 52ch, then a 1px rule and a two-column key-value grid (`grid-template-columns:auto 1fr; gap:6px 22px`, keys `--fg-dim`, values `--fg`) for `focus` / `team` / `reach`. Links inline, `$blue`, underlined.

### 3. Post — `_layouts/post.html`, option `2a` card 3 / `3b` card 3

Desktop: tabline on top (`posts/` breadcrumb + active filename with a 2px bottom border in the category color), then `[ gutter 54px | article ]`, then statusline. Article padding `24px 40px 0 16px`.

- Meta line: `PWN · 2026-08-14 · 11 MIN · X86-64 / GLIBC 2.39`, 11px, `.05em`, category word in the category color.
- `h1` 24px/1.2/700.
- Optional TL;DR block: `1px solid --rule` + `2px` left border in the category color, `10px 12px`, label `TL;DR` (10px, `.12em`, category color), text 12px `--fg-mid`.
- Body 13.5px/1.85, max 50ch. `em` renders `--fg-mid` italic. Inline `code` is `$cyan` on `--bg-sunk`, `1px 4px` padding, no radius.
- Code blocks: `--bg-sunk` background, `2px` left border `$green`, `12px 16px`, 12.5px/1.8. Shell prompts `$` in `--fg-dim`, command in `$green`, string args `$cyan`, comments `--fg-dim`.
- If `toc: true`, a 168px left sidebar between gutter and article: `CONTENTS` label + `[1] …` numbered entries, current entry `--fg-mid`, plus a `TAGS` block below. Generate the ToC from `h2`s in Liquid (`content | split: '<h2'`) or with a tiny JS pass on `article h2` — JS is acceptable here since it's decorative.
- Statusline: mode block = category color, filename = `posts/YYYY/slug.md`, right cells `ln 42/318` (fake it: current scroll line ≈ `progress × total lines`, total from `content | number_of_lines`) and a percentage cell on `--bg-chrome` darkened.

Mobile (`3b`): tabline dropped; a 2px scroll-progress bar in the category color sits directly under the status bar. Padding `22px 20px 0`. Body 15px/1.75. Statusline keeps the mode block (44px tall) and a `:` button on the right.

### 4. `:` command palette — `_includes/palette.html` + `palette.js`

**Desktop** (`2a` card 2): opens on `:` keypress (and on `/` prefilled as `:search `). Absolutely positioned strip anchored `bottom: 30px` (i.e. directly above the statusline), full width, `--bg-sunk`, `1px` top rule. Input row: `9px 16px`, 13px, `$blue` colon then typed text then a block cursor (`background:#93a1a1; color:var(--bg)` on the character after the caret). Results below, `5px 16px` each, 12.5px: command name in its category/accent color at fixed 76px width, description `--fg-dim`. Selected row background `--bg-chrome`. `Esc` closes, `↑/↓` moves, `Enter` navigates. Mode block switches to `COMMAND` in `$blue`.
**Important:** the palette must cover whole result/content rows — do not let it half-clip a line of text behind it.

**Mobile** (`3b` card 2): same data as a bottom sheet. Backdrop = page at `opacity:.35`. Sheet `--bg-sunk`, `16px 16px 0 0`, drag handle `34×3px` `--bg-chrome`. Rows `11px 18px` (≥44px tall), command 13px in accent color at 76px width, description 11.5px. Opens by tapping the mode block or the `:` cell; closes on backdrop tap, swipe-down, or `Esc`.

Commands come from `_data/commands.yml`:

```yaml
- { cmd: ":posts",  desc: "all 37 write-ups",  url: "/posts/",       color: "#b58900" }
- { cmd: ":cheat",  desc: "cheatsheet index",  url: "/cheatsheets/", color: "#2aa198" }
- { cmd: ":about",  desc: "who's typing",      url: "/about/",       color: "#d33682" }
- { cmd: ":theme",  desc: "light / dark",      action: "theme",      color: "#6c71c4" }
- { cmd: ":rss",    desc: "subscribe",         url: "/feed.xml",     color: "#268bd2" }
```

`:search` should filter over a build-time JSON index — emit `search.json` from a Liquid template (title, url, category, date, `content | strip_html | truncatewords: 60`) and fuzzy-match client-side. No Algolia, no Lunr dependency needed at this size; a simple subsequence scorer is enough.

The palette is **progressive enhancement**: with JS off, `_includes/palette.html` must still render the same list as a plain `<nav>` of links in the footer.

### 5. Image / figure treatments — `_includes/figure.html`, option `2c`

All four share: `--bg-sunk` background, `1px solid --rule`, no radius, caption **below** the frame as a vim comment — a `"` in `--fg-faint` then the caption text in `--fg-dim` at 11.5px.

```liquid
{% raw %}{% comment %} {% include figure.html src="frame-before-ret.png" alt="..." 
   caption="fig 1 — saved RBP at rsp+0x18" mode="inline|bleed|twoup" 
   src2="after.png" label2="after.png" %} {% endcomment %}{% endraw %}
```

1. **`inline`** (default) — header bar inside the frame: `6px 11px`, `1px` bottom rule, `$green ▸`, filename in `--fg`, right-aligned hint `<CR> zoom` in `--fg-dim`. Image below, `width:100%`, `height:auto`.
2. **`bleed`** — for wide diagrams. Breaks the content column and the gutter: `margin-left: calc(-1 * (var(--gutter-w) + var(--pad-l)))`, full viewport width, only top/bottom rules. Caption returns to the text column's left edge. Mobile: `margin: 0 -20px`.
3. **`twoup`** — before/after. `display:flex; gap:2px` inside one `1px` border, each half with its own `5px 10px` filename bar, one shared caption.
4. **`attachments`** (`_includes/attachments.html`) — quickfix strip at the end of a post. Header `:copen — N attachments` (10.5px, `--fg-dim`), then `display:flex; gap:10px; padding:11px`, each thumb `1px` bordered with the filename 10px below.

**Zoom / lightbox** (`lightbox.js`): clicking any figure (or `Enter` on a focused one) opens fullscreen — backdrop `#00181f`, image centered with `16px` padding, caption line `fig 1 of 4 — filename.png · 2048×1180`, and a statusline with a `$violet` `ZOOM` mode block, `h/l next · q close`, and an `n/N` counter. Mobile: pinch-zoom and swipe between figures. Respect `prefers-reduced-motion` (no scale animation, just a 120ms opacity fade).

**Image pipeline:** author drops PNGs in `assets/img/posts/<slug>/`. Screenshots are terminal captures — do **not** convert them to JPEG (text ringing); keep PNG, run `oxipng -o4` in CI. Add `width`/`height` attributes on every `<img>` to prevent layout shift, `loading="lazy"` on all but the first, `decoding="async"`. If a post has more than ~6 screenshots, add `jekyll-picture-tag` and emit 2 srcset widths (`720w`, `1440w`); otherwise skip the plugin.

### 6. Cheatsheet index + page — `cheatsheets.md`, `_layouts/cheatsheet.html`

Not mocked; build it as the post layout with two changes: a `CHEAT` `$cyan` mode block, and body content laid out as a two-column `grid-template-columns: auto 1fr; gap: 4px 20px` key/value list (key = the keystroke or command in `$cyan`, value = description in `--fg`) so cheatsheets scan without prose. Index page = a flat list of cheatsheets grouped by tool, same row grammar as the home post list.

### 7. Tags page, 404

`tags.md` — categories as a row of `1px` bordered chips (`2px 7px`, 11px, category color, count in `--fg-dim`), then the filtered post list below, filtering client-side with no page reload. `404.html` — statusline mode block `$red`, mode text `E486`, message `pattern not found: <path>` and a link home.

---

## Theming

`data-theme="dark|light"` on `<html>`; dark is the default. `theme.js`: read `localStorage.theme`, else `prefers-color-scheme`, apply **before first paint** via a tiny inline script in `<head>` to avoid a flash. Toggle via `:theme` in the palette. Light mode is the `1b` treatment: `#fdf6e3` page, `#eee8d5` chrome, `#e4dcc4` rules, `#cfc7ae` gutter digits, statusline text `#fdf6e3` on the accent block. Rouge needs both a dark and a light Solarized stylesheet, scoped under the `[data-theme]` attribute.

## Interaction inventory

- `:` open palette · `/` search · `Esc` close · `↑↓`/`Ctrl-n`/`Ctrl-p` move · `Enter` go
- `j`/`k` move selection in post lists, `Enter`/`o` open, `gg`/`G` jump to top/bottom
- `Enter` or click on a figure → zoom; `h`/`l` between figures; `q` closes
- `?` opens a keybinding cheat overlay (same sheet component as the palette)
- Hover on list rows: title → `--fg-strong`, gutter digit → `$yellow`, 90ms `ease-out`
- No page transitions, no scroll animation, no parallax. Transitions only on color (90ms) and the palette/sheet (140ms `cubic-bezier(.2,.8,.2,1)` translate). Kill all of it under `prefers-reduced-motion`.
- Every keyboard shortcut must have a pointer equivalent; nothing is keyboard-only.

## Accessibility

Contrast: `--fg` on `--bg` is 6.5:1 — fine. `--fg-dim` (`#586e75` on `#002b36`) is only ~3.0:1, so **restrict it to non-essential meta text** and never use it for body copy or the only copy of a label. Gutter digits are decorative → `aria-hidden="true"`. Provide a skip link to `<main>`. Visible focus ring: `2px solid $blue`, `outline-offset: 2px` (never `outline: none`). The statusline is decorative chrome — mark the real nav with `<nav aria-label="Site">`. Every figure is `<figure>` + `<figcaption>`; the `"` glyph in the caption is `aria-hidden`.

## Build, quality gates, deploy

```bash
bundle install
bundle exec jekyll serve --livereload      # dev
JEKYLL_ENV=production bundle exec jekyll build
```

CI (GitHub Actions): `jekyll build` → `html-proofer` (broken links, missing alt text, missing image dimensions) → `oxipng` check → deploy `_site`. Targets: Lighthouse ≥ 98 performance, total JS under 12KB gzipped (four small vanilla files, no framework, no jQuery), no render-blocking requests beyond one CSS file and the four woff2 preloads.

RSS: `jekyll-feed` at `/feed.xml`; also expose `/feed.json`. Link both in `<head>` and from `:rss`.

## Open items for the site owner

1. Real name, handle, links (GitHub / Matrix / PGP fingerprint), and the about copy.
2. Whether cheatsheets should also appear in the main post list (mockups show them mixed in — `2a` home lists a `cheat` entry).
3. Disclosure policy text — `1c`'s about panel had a "90 days, then it goes up" note that may be worth keeping as a `/disclosure/` page.
4. Comments: none in the design. If wanted later, a static option (giscus) fits the no-server constraint.

## Files in this bundle

- `README.md` — this document.
- `Personal Site Mockups.dc.html` — the design reference. Open in a browser; scroll to turn 2 and turn 3.
- `support.js` — runtime the mockup file needs to render. Not part of the site build.
