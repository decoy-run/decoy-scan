# decoy-scan — Agent Reference

MCP supply chain security scanner. Zero dependencies. Node.js >= 18.

## Install & Run

```bash
npx decoy-scan                        # full scan
npx decoy-scan --json                 # machine-readable output
npx decoy-scan --sarif                # SARIF 2.1.0 for CI/CD
npx decoy-scan explain <target>       # explain a tier / category / tool name
npx decoy-scan explain <target> --json  # structured explanation
```

## What This Tool Does

Scans local MCP client configurations, spawns each configured server via stdio, queries its tool list, and analyzes everything for security and readiness issues.

## Scan Categories

1. **Tool risk classification** — classifies every tool as critical/high/medium/low based on name patterns and description analysis
2. **Tool poisoning detection** — 37 regex patterns across 20 categories detecting prompt injection hidden in tool descriptions (instruction override, concealment, data exfiltration, credential harvesting, coercive execution, tool shadowing, evasion techniques)
3. **Server command analysis** — checks spawn commands for pipe-to-shell, temp directories, inline code, typosquatting, network tools
4. **Environment variable exposure** — flags 12 categories of sensitive credentials passed to MCP servers (API keys, tokens, passwords, database URLs, cloud credentials)
5. **Production readiness** — checks for missing descriptions, missing schemas, no required fields, overloaded scope, destructive tools without safety hints
6. **Supply chain advisories** — cross-references against Decoy advisory database (40+ MCP packages)
7. **OWASP mapping** — maps all findings to OWASP Agentic Top 10 (ASI01, ASI02, ASI03, ASI05)

## Architecture

```
decoy-scan/
├── index.mjs      — library (all exports)
├── bin/cli.mjs    — CLI entry point
├── package.json   — zero dependencies, ES modules
├── README.md      — human docs
├── AGENTS.md      — this file (agent docs)
├── CONTRIBUTING.md
└── LICENSE         — MIT
```

## Library Exports

```javascript
import {
  scan,              // Full scan: discover + probe + classify + check
  classifyTool,      // Classify a single tool's risk level
  detectPoisoning,   // Detect prompt injection in tool descriptions
  analyzeServerCommand, // Check server spawn command for suspicious patterns
  analyzeEnvExposure,   // Flag sensitive env vars passed to servers
  analyzeReadiness,     // Production readiness heuristics
  discoverConfigs,      // Find MCP config files on this machine
  probeServer,          // Spawn and query a single MCP server
  checkAdvisories,      // Fetch advisory database from Decoy API
  matchAdvisories,      // Match server against advisories
  toSarif,              // Convert results to SARIF 2.1.0
  mapToOwasp,           // Map finding type to OWASP category
} from 'decoy-scan';
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `--json` | JSON output (machine-readable) |
| `--sarif` | SARIF 2.1.0 output (GitHub Security, VS Code) |
| `--brief` | Minimal JSON summary (implies `--json`) |
| `--no-probe` | Config-only scan (don't spawn servers) |
| `--no-advisories` | Skip Decoy advisory database check |
| `--share` | Generate a shareable public URL for results |
| `--yes`, `-y` | Skip confirmation prompts (for CI use) |
| `--verbose`, `-v` | Show all tools including low-risk |
| `--quiet`, `-q` | Suppress status output |
| `--version`, `-V` | Print version |
| `--help`, `-h` | Print help |

## `explain` subcommand

For resolving what a scan finding means without parsing the full scan output.
Useful when an agent sees a finding and needs structured context to act on it.

```bash
decoy-scan explain critical              # severity tier
decoy-scan explain tool-description      # finding category
decoy-scan explain prompt-override       # poisoning type
decoy-scan explain read_file             # tool name (runs real classifier rules)
decoy-scan explain list                  # enumerate all explainable targets
decoy-scan explain <target> --json       # structured output (preferred for agents)
```

`--json` output shape:

```json
{
  "tool": "decoy-scan",
  "version": "0.5.1",
  "target": "critical",
  "result": {
    "kind": "tier",
    "key": "critical",
    "title": "Critical",
    "summary": "Can execute code, modify data, or cause irreversible changes.",
    "body": "...",
    "examples": ["execute_command", "write_file", "..."],
    "advice": "..."
  }
}
```

`result.kind` is one of `tier`, `category`, `poisoning`, or `tool`. `tool`
results include `risk`, `reason`, `matched` (the regex that matched by name),
and a `note` when classification relied on name alone (real scans also use
the tool description).

## `--brief` Output Schema

`--brief` implies `--json` — passing it alone is enough. The output is a
minimal summary object:

```json
{
  "servers": 3,
  "critical": 1,
  "high": 2,
  "medium": 4,
  "low": 5,
  "poisoned": 0,
  "status": "fail",
  "exitCode": 2
}
```

Fields:
- `servers` — number of non-decoy, non-error servers scanned
- `critical`, `high`, `medium`, `low` — tool risk counts
- `poisoned` — number of tool poisoning findings
- `status` — `"pass"` (clean), `"warn"` (high-risk), or `"fail"` (critical/poisoned/toxic flows)
- `exitCode` — matches the process exit code (see below)

## Exit Codes

- `0` — No critical or high-risk issues
- `1` — High-risk issues found
- `2` — Critical issues or tool poisoning found

The exit code is also surfaced as `exitCode` on `--json` and `--brief`
output, so agents can branch on it without re-deriving severity from
`summary` counts.

## Supported Hosts (7)

Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, Cline

Config paths are platform-aware (macOS, Windows, Linux).

## JSON Output Schema

```json
{
  "timestamp": "ISO-8601",
  "hosts": ["Claude Desktop", "Cursor"],
  "servers": [{
    "name": "server-name",
    "hosts": ["Claude Desktop"],
    "command": "npx",
    "args": ["@modelcontextprotocol/server-filesystem"],
    "tools": [{
      "name": "read_file",
      "description": "...",
      "risk": "high",
      "poisoning": [{ "type": "...", "severity": "...", "description": "..." }]
    }],
    "risk": "high",
    "error": null,
    "findings": [{
      "type": "env-exposure",
      "severity": "high",
      "description": "...",
      "source": "env-config"
    }]
  }],
  "summary": {
    "total": 2, "critical": 1, "high": 0, "medium": 0, "low": 1,
    "errors": 0, "poisoned": 0, "suspicious": 0, "envExposures": 1, "readiness": 0
  },
  "advisories": [],
  "owasp": {
    "ASI02": { "id": "ASI02", "name": "Unsafe Tool Use", "count": 5 }
  }
}
```

## MCP Handshake Protocol

The scanner follows the proper MCP initialization sequence:
1. Send `initialize` request (id: 1)
2. Wait for `initialize` response
3. Send `notifications/initialized`
4. Send `tools/list` request (id: 2)
5. Read tools from response

15-second timeout per server. Servers are killed after tool list is received.

## Contributing

See CONTRIBUTING.md. Key principles: zero dependencies, no build step, read-only (never modify configs).
