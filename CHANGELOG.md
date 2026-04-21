# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
