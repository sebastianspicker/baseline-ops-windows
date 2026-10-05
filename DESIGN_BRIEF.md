# Design brief: BaselineOps browser tour

This brief covers the redesign of the static browser tour in `docs/demo/`,
which is published to GitHub Pages and captured for the README screenshots.
It is a working document for review and is not part of the release package.

## Product summary

BaselineOps for Windows is a PowerShell toolkit that audits Windows
endpoints, investigates configuration drift, and collects diagnostic
evidence. It ships 52 numbered capabilities (`01-*` to `52-*`), six `00-*`
orchestration scripts, seven reviewed example profiles, and a Windows Forms
launcher. Some capabilities can remediate, but only behind `ShouldProcess`,
confirmation, and protected-install checks. Every run produces a v2 result:
`Result` (`OK`, `WARN` or `FAIL`), exit code `0`, `2` or `1`, and a list of
findings with code, severity and message.

The browser tour is the product's only web surface. It never runs
PowerShell. It shows three real example profiles, builds an exact
`00-Run-Profile.ps1` command, and explains one fictional Defender result.

**Moment of value:** the visitor sees the exact command they would run, and
can trust it because it is built from a profile they have just read. The
result step then shows that the output is evidence they can inspect, not a
verdict.

## Audience

**Primary: Windows endpoint administrators and security engineers.** They
work in small and mid-sized IT teams, MSPs, schools and universities, and run
Intune, ConfigMgr, or plain GPO plus scripts. They live in PowerShell, Event
Viewer, Windows Terminal, the Defender portal, and ticket systems.

- **Goals:** know the real state of a fleet before changing it, produce
  evidence for an audit or incident, and hand a repeatable procedure to a
  colleague.
- **Anxieties:** running an unreviewed script as SYSTEM, a tool that changes
  settings when it says it only audits, and noisy "compliance scores" that
  hide what was actually checked.
- **What they distrust:** marketing gradients, vague claims, dashboards
  without raw data, and anything that hides the command.
- **What signals quality to them:** precise nouns (exit codes, parameter
  names, file names), visible raw JSON, conservative defaults, honest
  labelling of what is sample data, and documentation that reads like a
  runbook.

**Secondary:** reviewers evaluating the repository (security leads,
contributors) who arrive from the README and want to judge rigor in a minute.

## Key journeys

1. **Choose a profile:** pick one of three profiles, read the execution
   order, and inspect the raw profile JSON.
2. **Prepare an audit:** choose an output format, optionally add `-WhatIf`,
   and copy the command.
3. **Read a result:** see a `WARN` result with exit code 2, filter findings
   by severity, inspect or download the v2 JSON.
4. **Leave for Windows:** open the release guide, script catalog, or
   launcher guide on GitHub.

## Brand traits

| Trait | Not |
| --- | --- |
| Deliberate: every action is visible before it happens | Timid or bureaucratic |
| Exact: names, numbers, and codes are shown verbatim | Cryptic or jargon-heavy |
| Candid: sample data and limits are labelled plainly | Apologetic or legalistic |
| Calm: a warning is a place to start | Alarmist or "security theatre" |
| Workmanlike: it looks like a tool someone maintains | Austere or unfinished |

## Market observations

Typical neighbours are endpoint and compliance tools such as vendor MDM
consoles, compliance-as-code scanners, CIS benchmark tooling, and
open-source PowerShell hardening projects.

- **Conventions worth honouring:** visible commands in monospace,
  severity colour coding, raw output access, and links to source.
- **Conventions worth breaking:** dark "cyber" hero sections with neon
  accents, shield and padlock iconography, compliance percentage gauges,
  card grids of features, and a big dashboard screenshot.

None of the obvious neighbours present themselves as a reviewed
*procedure*. That is BaselineOps' actual stance: read, then run.

## What to keep

- The existing brand green (`#254f42`) and the `B/` monogram. Both are
  modest and already appear in the README screenshots.
- The copy voice. "Know the state. Review the next step." and "Read first.
  Run deliberately." are specific and correct. Keep them and tighten the
  rest.
- The three-step structure and all behaviour in `app.js`.
- The strict CSP: no external fonts, scripts, or images.

## Current weaknesses

- The page reads as a competent generic SaaS layout: a hero with a side
  note, a stat strip, then a tabbed card with a soft shadow. Nothing about
  it says "endpoint procedure".
- Type has no character. It uses the system font throughout, with heavy
  negative tracking on the heading that becomes cramped on Windows.
- The profile metadata (`Mode`, `Arguments`, `Signed scripts required`) is
  hard-coded in HTML rather than read from the profile. It is accurate today
  but could drift.
- Script names are shown only as full file names. The capability number,
  which is the main way operators refer to scripts ("run 27"), has no
  weight.
- The result step shows `WARN · EXIT 2` but never explains the exit-code
  scheme it belongs to.
- There is no dark-scheme support, although the audience mostly works in dark
  terminals.
- On mobile the step tabs wrap into cramped three-line buttons, and the
  stat strip wraps unevenly.

## Constraints

- **Files:** only `docs/demo/index.html`, `styles.css`, `app.js` and
  `profiles.json` may exist in `docs/demo/`, because `tools/verify.ps1`
  enforces the public-documentation allowlist. Self-hosted font files would
  therefore need a reviewed allowlist change, and the CSP blocks external
  fonts. **Decision: use system fonts only.**
- **Behaviour contracts:** `dev/demo/verify.mjs` drives the page through
  these IDs and selectors: `#profile`, `#script-list li`, `#profile-json`,
  `#next-step`, `[data-step]`, `#command`, `#command-text`, `#output`,
  `#whatif`, `#copy-command`, `#announcement`, `#result`, `#severity`,
  `#findings article`, `#download-result`, `#result-json`,
  `#result summary`, `#load-error`, `.skip`, `#workspace`, `noscript`.
  `#command-text` must contain only the command, because the clipboard test
  compares the two.
- `profiles.json` is generated by `dev/demo-profiles.mjs` and must not be
  edited by hand.
- **Layout:** no horizontal overflow at 320, 390, 768 or 1440 px.
- **Accessibility:** WCAG 2.2 AA, keyboard operation, and a skip link.
- **README screenshots:** captured at 1440 px by `npm run screenshots`.

## Assumptions log

| Assumption | Evidence | Confidence |
| --- | --- | --- |
| Primary visitors are Windows admins viewing on Windows | Product is Windows-only; README audience and requirements | High |
| Bahnschrift and Segoe UI Variable are present on visitors' machines | Bahnschrift ships with Windows 10 1709+; Segoe UI Variable with Windows 11 | Medium |
| Cascadia Mono is present on many visitors' machines | Bundled with Windows Terminal and recent Windows 11; Consolas fallback otherwise | Medium |
| Visitors on macOS/Linux are a meaningful minority (reviewers) | GitHub traffic from README; contributors use macOS (see AGENTS.md host notes) | Medium |
| Many visitors prefer a dark scheme | Admin tooling defaults (Windows Terminal, VS Code) are dark | Medium |
| No self-hosted fonts are acceptable without a reviewed allowlist change | `tools/verify.ps1` allowlist; `docs/demo.md` says "no external fonts" | High |
| The page must stay a single static page with no build step | `pages.yml` uploads `docs/demo` as-is; `docs/demo.md` | High |
| Exit codes map OK→0, FAIL→1, WARN→2 | `lib/README.md` (`Get-V2ExitCode`) | High |

## Design direction

### Direction A: Run sheet (superseded)

**Concept.** The page is a reviewed operations procedure: the printed run
sheet a careful administrator attaches to a change ticket. It has a title
block, numbered steps, a margin for annotations, verbatim commands, and an
evidence slip at the end. This is BaselineOps' real stance (profiles are
procedures you read before you run), expressed as a document form. Admins
already trust this genre: change records, runbooks, and checklists.

**Typography.** The display face is a DIN-family grotesk, matching the
lettering of technical signage and engineering title blocks: Bahnschrift
on Windows, falling back to DIN Alternate on macOS and then to a neutral
system sans. Body text uses Segoe UI Variable, falling back to the platform
UI font. Code and data use Cascadia Mono, falling back to SF Mono and
Consolas. Pairing logic: DIN carries labels, numbers and headings (the
"form"), the UI font carries prose (the "instructions"), and mono carries
anything you could paste into a console (the "evidence"). Capability
numbers are set large in DIN figures, because operators say "run 27", not
"run Defender-Health-Audit".

Type scale: 12 / 13 / 15 / 17 / 22 / 30 / 44 / 68 px, using a perfect
fourth near the top and tighter steps for UI text.

**Colour.** Warm paper, near-black green ink, and one brand green for
action and selection. Two signal colours appear only where results do:
review amber for `WARN` and fault red for `FAIL`. A third ink tone is
reserved for rules. In the dark scheme the paper becomes a dim slate and
the inks invert, with no glow.

**Layout.** A two-column document grid: a 176 px margin rail for step
numbers and annotations, and a main column. Hairline rules replace cards.
Density is moderately high, as a runbook should be. Below 760 px the rail
folds into inline labels above each section, so mobile reads as a single
procedure, not a squeezed desktop.

**Motion.** Almost none. The incoming step panel fades in over 140 ms.
Copy feedback swaps the button label. Focus rings appear instantly. All of
this is disabled under `prefers-reduced-motion`.

**Signature details.**

1. **The title block.** A ruled grid in the header, like an engineering
   drawing's title block, records line, capability count, profiles, default
   mode, output formats, and "Device access: none". It replaces the stat
   strip with facts you could put in a change record.
2. **The exit-code key.** The result step carries a three-cell key
   (`0 OK · 2 WARN · 1 FAIL`) with the current result marked, so the
   warning is read as one state in a known scheme.

**Against the category.** No shield, no dark hero, no gauge, no feature
cards. It looks like paperwork done well.

**Refuses.** Icons, illustrations, shadows, rounded cards, gradients, and
scroll animations.

### Direction B: Console transcript

**Concept.** The page is a recorded PowerShell session. Each step is a
prompt, a command, and its output, scrolling like a transcript.

- **Typography:** all monospace (Cascadia Mono), with weight and colour as
  the only hierarchy.
- **Colour:** terminal dark background with the PowerShell 7 palette.
- **Layout:** a single column at 100 characters wide.
- **Motion:** typed-out commands.
- **Signature details:** a live prompt that echoes selected options.

It is faithful to the tool's medium, but it is the default look of every
developer tool, makes prose hard to read, and hides the "review before
running" stance behind a "just run it" aesthetic. It also implies the page
executes something, which the tour must never suggest.

### Direction C: Evidence ledger

**Concept.** The page is a case file. The profile is the scope, the
command is the procedure, and the result is an exhibit with a reference
number. Findings are rendered as indexed exhibits, and the layout uses a
wide table-led design with a running header.

- **Typography:** a serif for headings (Georgia or Sitka on Windows), with
  mono for exhibits.
- **Colour:** off-white with red reference marks.
- **Signature details:** exhibit stamps and a chain-of-custody header.

It is distinctive, but it leans on forensic and legal tropes. That
over-dramatises routine configuration audits, which the copy explicitly
says are "evidence for a decision, not a compliance certification".

### Choice

**Run sheet** fits best. It turns the product's central behaviour (read the
profile, see the command, then run) into the page's structure. It speaks
the audience's own genre (runbooks and change records). It works with the
system-font constraint, since Bahnschrift is DIN, and it keeps the existing
green and monogram.

**What it trades away.** It gives up the instant "developer tool"
recognition of the console look, and the drama of the ledger. On machines
without Bahnschrift or DIN, the display face falls back to the system sans.
The design must therefore hold up through scale, figures, and rules alone,
not through the typeface.

## Revision: technical document with Windows 98 controls

Review of the run-sheet build found that it still read as a generic landing
page: slogan headlines, a stat grid, uppercase micro-labels, tinted callouts,
and a cream-and-green palette. The tour was redesigned with the user's
approval, which also retired the brand green.

**Concept.** The page is a technical document, as security tools present
themselves: one 46rem column, plain headings, a real command up front, and
a "Boundaries" section that states what the toolkit will and will not do,
quoted from `README.md`, `docs/architecture.md` and `SECURITY.md`. Only the
interactive walkthrough is styled as an application: a Windows 98 dialog.

**Typography.** Segoe UI for prose, Cascadia Mono for anything you could
paste into a console, and Tahoma for window chrome only (title bars, tabs,
buttons, field labels). No display face and no uppercase labels.

**Colour.** Cool neutral greys. Navy (`#000080`) for links and selection,
as in Windows 98. Commands and JSON sit on the PowerShell console blue
(`#012456`) in both schemes. Amber and red appear only in results. The
dark scheme keeps the same chrome with dark bevels.

**Windows 98 elements.** Bevelled buttons with an inner dotted focus
rectangle, sunken fields with a raised drop-down button, property-sheet
tabs, and navy-to-blue gradient title bars on the dialog and on command
windows. There are no fake window buttons, no teal desktop, and no pixel
fonts. Corners are square everywhere.

**Motion.** None beyond the browser's smooth scroll to the walkthrough,
which is disabled under `prefers-reduced-motion`.
