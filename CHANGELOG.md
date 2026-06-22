# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.9.0] - 2026-06-22

### Added
- **Supply-chain source integrity** (`analyzePackageSource`). A static scan
  can't see what a package *will* resolve to, but it can see whether the config
  lets it change at all. Two configurations re-fetch code on every launch with
  no review, and both are now flagged:
  - **`unpinned-remote-source`** (high) — the server runs code straight from a
    remote/VCS/URL source (`github:`, `git+https://`, a raw `https://` module)
    instead of a pinned registry package.
  - **`unpinned-dist-tag`** (medium) — the package is pinned to a moving tag
    (`@latest`, `@next`, `@beta`, …) that re-resolves on every launch.

  Both map to OWASP **ASI03 (Supply Chain Risk)**. Bare unpinned `npx pkg` (no
  version) is the documented norm for MCP servers and is deliberately **not**
  flagged — only genuinely-mutable sources are, to hold the zero-noise bar.
  Parses through wrapper commands (`node proxy.mjs -- npx pkg@latest`) and the
  `--package` / `--spec` flags of `pipx` / `uvx` / `deno run` / `bunx` / `dlx`.
- New public export: `analyzePackageSource`.

### Verified
- Suite 154 → 167 (+13 cases). Live scan smoke flagged a `github:` source (high)
  and `@latest` (medium), and correctly stayed silent on pinned versions, bare
  unpinned `npx`, and local paths. On real machine configs it caught two servers
  genuinely running `@latest` through a proxy wrapper — zero false positives.

## [0.8.1] - 2026-05-14

### Changed
- **Findings-aware closing output.** The end-of-run claim line was a
  generic "See your dashboard: <url>" footnote, disconnected from the
  scan that just ran. It now ties the CTA to the result — `3 findings —
  keep them past this terminal:` with a one-line value note (history,
  re-scan diffs, severity review). Honest framing: terminal output is
  ephemeral; the dashboard makes it persistent and diffable. The
  CLI→account claim flow itself was verified working end-to-end in
  production; the gap was that the handoff had no force behind it.

## [0.7.0] - 2026-05-10

### Added
- **v2 telemetry envelope.** Every event now carries `schema_version`,
  `event_id` (for server-side dedup), `run_id` (groups events from one
  invocation), `ts`, and an `env` block with `node`, `platform`, `arch`,
  `ci` flag, MCP `host` (claude-desktop / cursor / windsurf / vscode /
  claude-code / zed / cline / ci / cli), and `locale`. Lets us segment
  cohorts and answer questions like "Linux CI users convert 3x more
  than macOS dev users" — table-stakes business data.
- **New events:** `cli.invoked` (funnel denominator — fires first
  thing, before any work, so even bounced/crashed runs are counted),
  `scan.discovery` (what hosts/servers the user has — single most
  useful "who is this user" signal), and renamed event names to dotted
  form (`scan.complete`, `scan.uploaded`).
- **Retry + persistent queue.** 1 retry with 200→800ms backoff on
  transient failures. Final failures append to
  `~/.decoy/telemetry-queue.jsonl` (FIFO, capped at 1000 events). The
  next CLI run drains the queue as a single batched POST before doing
  anything else. Network flakiness no longer drops events.
- **First-run dashboard link.** The CLI prints
  `See your dashboard: https://app.decoy.run/d/<installId>` at the end
  of every human-mode run. Clicking links the install_id to your
  account, claiming pre-signup history.

### Changed
- Legacy `send()` helper still works — it now maps v1 event names to
  v2 internally and emits the new envelope. Old CLI tests pass without
  changes.

## [0.6.2] - 2026-05-10

### Fixed
- **Telemetry now fires when no MCP configs are found.** Previously
  the CLI exited at the empty-discovery branch (`bin/cli.mjs:438`)
  *before* the telemetry call site, so every first-time
  `npx decoy-scan` in a fresh dir without an MCP client configured
  bounced silently and we never learned anyone tried. Now sends a
  `scan_complete` event with `{noConfigs: true}` payload before
  exiting. This was the dominant reason real-user telemetry was at
  zero for the 0.6.0/0.6.1 rollout.

## [0.6.0] - 2026-05-10

### Added
- **`--verify` flag.** AI-revalidates scan findings via `/api/verify`: Haiku 4.5
  triages each finding into P0/P1/P2, then Sonnet 4.6 revalidates P0/P1 and
  drops false positives. Free tier gets 5 verifications/installId/month;
  Team+ unlocks unlimited. Output shows raw vs verified counts and the
  reasoning the model used.
- **Anonymous telemetry (default-on).** Every scan now reports a redacted
  finding summary (counts, OWASP categories, finding sources — never raw
  tool descriptions, paths, or arguments) to `/api/telemetry`. Identified by
  a stable `~/.decoy/install_id` UUID, not by email or hostname. On signup,
  the install_id links pre-account history to the new account. Disable with
  `DECOY_TELEMETRY=0` env var or `--no-telemetry` flag. See
  https://decoy.run/privacy for what's collected.
- **`--no-telemetry` flag** for opting out per-run.
- **First-run telemetry notice** (one line, once per machine, cached at
  `~/.decoy/telemetry-notice-shown`).

### Changed
- **`explain` command split into free meaning + paid remediation.** The
  "what it is" and "why it matters" content stays free. The "how to fix"
  remediation block now requires a Team+ token. Tier is resolved via
  `/api/billing` and cached at `~/.decoy/tier` for 24h.
- **Upgrade prompts now anchored on actual finding count.** Replaces the
  generic `--report` prompt with `npx decoy-scan --verify  # AI-verify N findings`.

## [0.5.8] - 2026-05-06

### Added
- Scan output now ends with a one-line GitHub star ask. Mirrors the same line
  in `decoy-tripwire` and `decoy-redteam`, so users running multiple Decoy
  CLIs see consistent post-run output.

## [0.5.7] - 2026-04-28

### Fixed
- `--report` and `decoy-scan login` now open
  `https://app.decoy.run/dashboard?tab=settings#s-setup` (the Setup & Tokens
  section) instead of the dashboard overview. Previously users landed on the
  overview page and had to hunt for where to copy their token, dropping the
  signup-to-first-upload conversion rate. The token-regenerate hint shown
  on auth failure now points to the same anchor.

## [0.5.6] - 2026-04-28

### Added
- `--json` and `--brief` output now includes an `exitCode` field so agents
  consuming the JSON don't have to re-derive severity from `summary` counts.
  Matches the process exit code (0/1/2) defined in `--help`.

### Changed
- `--brief` now implies `--json` (it has always been a JSON-only form per
  `--help`). Previously `--brief` alone produced no stdout — agents had to
  remember to also pass `--json` for the brief summary to surface.

### Fixed
- `classifyTool` and `explain <tool>` were anchoring every name pattern,
  so suffixed code-execution names slipped through to "low" — most
  visibly `evaluate_script` (the one shipped by `chrome-devtools` MCP),
  plus `eval_code`, `execute_script`, `execute_python`, `run_javascript`,
  `run_sql`, etc. Two changes:
  - Added `^eval[_-]?(script|code)$`, `^evaluate[_-]?(script|code)$`,
    `^execute[_-]?(script|code|js|javascript|python|sql)$`,
    `^run[_-]?(script|code|js|javascript|python|sql)$` to the critical
    tier in `RISK_PATTERNS`.
  - The substring fallback (previously description-only) now also runs
    against the lowercased name, so risky verbs like `evaluate`,
    `spawn`, `fetch` classify correctly even when no description is
    provided. Tested in `unit.test.mjs` and `cli.test.mjs`.

## [0.5.4] - 2026-04-25

### Fixed
- `explain --json` no longer appends a second JSON payload to stdout when
  no MCP configurations are present. The CLI was falling through from the
  `explain` branch into `main()` because `exitWhenDrained()` defers the
  actual exit; added a guard so `main()` only runs when no subcommand
  matched. Surfaced as test failures on Node 22 in CI.

## [0.5.1] - 2026-04-21

### Changed
- README now documents the `explain` subcommand with examples.
- AGENTS.md documents `explain` for AI agents, including the `--json` shape
  and the four `result.kind` values (`tier`, `category`, `poisoning`, `tool`).

## [0.5.0] - 2026-04-21

### Added
- New `decoy-scan explain <target>` subcommand. Resolves against severity
  tiers, finding categories, poisoning types, and tool names — all sourced
  from the same `RISK_PATTERNS` and `POISONING_PATTERNS` the scanner uses,
  so explanations can't drift.
- `explain list` enumerates everything explainable. `--json` supported on
  every path for agent consumption.

### Changed
- Pretty CLI output overhaul (JSON/SARIF/`--brief` unchanged):
  - Two progress lines at the top of a run (`▸ Discovering MCP servers…`,
    `▸ Running N checks…`) and a one-line severity legend before results.
  - Per-server header is a badge: `✗ name N critical`, `! name poisoned tool`
    (magenta), `? name probe failed`, `✓ name passed`.
  - Severity labels (Critical, High, Medium) introduce each tool group;
    Low collapses to a count instead of listing safe tool names.
  - Long tool and error lists wrap with a proper hanging indent.
  - Summary reads `N issues found · N critical, N high · N checks passed · Ns`
    with a one-line review guidance — replaces opaque "issues blocked".
- High-risk items render in orange (previously red, indistinct from critical).
- Poisoned tool findings get a magenta `!` badge.
- Muted gray (ANSI 256-color 252) introduced for readable secondary text,
  so dim is reserved for truly tertiary content.
- Decoy tripwire servers deduplicate across host configs (same server name
  in multiple hosts shows once).

### Fixed
- Servers that failed to probe no longer misleadingly show as "passed" —
  they get a `? probe failed` badge and the error wraps with proper indent.
- `--sarif` and `--json` output could be truncated when piped to another
  command (e.g. `decoy-scan --sarif | jq`). Root cause was `process.exit()`
  killing Node before stdout drained. The CLI now waits for the pipe to
  flush before exiting.

## [0.2.0] - 2026-03-20

### Added
- SSE transport security checks
- Input sanitization validation (schema completeness, type constraints, pattern validation)
- Explicit permission scope scoring
- Dynamic tripwire detection

### Changed
- Session telemetry improvements

## [0.1.0] - 2026-03-15

### Added
- Initial release: MCP supply chain security scanner
- Config file detection for Claude Desktop, Cursor, VS Code, and more
- Tool risk analysis and vulnerability scanning
- Suspicious server detection
- CLI interface (`decoy-scan`)
