# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
