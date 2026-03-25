# decoy-scan

Find security risks in your MCP servers before attackers do. Zero dependencies, zero config, zero account required.

[![npm](https://img.shields.io/npm/v/decoy-scan)](https://www.npmjs.com/package/decoy-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```bash
npx decoy-scan
```

Scans Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, and Cline. Finds risky tools, detects prompt injection, analyzes toxic data flows, tracks manifest changes, and maps everything to the OWASP Agentic Top 10.

## What It Checks

| Check | What it finds |
|-------|---------------|
| Tool risk classification | Critical/high/medium/low tools by name + description |
| Prompt injection detection | 37 patterns across 20 attack categories in tool descriptions |
| Toxic flow analysis | Cross-server data leak (TF001) and destructive (TF002) attack chains |
| Tool manifest hashing | Detects tool additions, removals, and description changes between scans |
| Skill scanning | Prompt injection, hardcoded secrets, suspicious URLs in Claude Code skills |
| Server command analysis | Pipe-to-shell, inline code, typosquatting, temp directory spawning |
| Environment variable exposure | API keys, tokens, secrets, cloud credentials passed to servers |
| Supply chain advisories | 40+ known vulnerable MCP packages via Decoy advisory database |
| Transport security | HTTP without TLS, missing auth, wildcard CORS, public-bound SSE |
| Input sanitization | Unconstrained parameters, missing maxLength, open schemas |
| Permission scope | Over-privileged servers, dangerous capability combinations |
| OWASP mapping | Every finding mapped to ASI01–ASI05 |

## CI/CD Integration

Three lines of YAML. Breaks the build on any policy violation.

```yaml
# .github/workflows/mcp-security.yml
- run: npx decoy-scan --policy=no-critical,no-toxic-flows,require-tripwires
- run: npx decoy-scan --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Policy Gate

Configurable policies for CI/CD pipelines:

```bash
npx decoy-scan --policy=no-critical              # Fail on critical tools
npx decoy-scan --policy=no-toxic-flows           # Fail on toxic data flows
npx decoy-scan --policy=require-tripwires         # Fail if decoy-mcp not installed
npx decoy-scan --policy=no-poisoning             # Fail on prompt injection
npx decoy-scan --policy=no-secrets               # Fail on exposed env vars
npx decoy-scan --policy=max-high=5               # Fail if >5 high-risk tools
npx decoy-scan --policy=no-critical,no-toxic-flows,require-tripwires  # Combine
```

## Options

```bash
npx decoy-scan                     # Full scan with server probing
npx decoy-scan --json              # JSON output (stdout, pipeable to jq)
npx decoy-scan --sarif             # SARIF 2.1.0 for GitHub Security / VS Code
npx decoy-scan --skills            # Also scan Claude Code skills
npx decoy-scan --no-probe          # Config-only (don't spawn servers)
npx decoy-scan --no-advisories     # Skip advisory database check
npx decoy-scan --report            # Upload results to Decoy dashboard
npx decoy-scan --policy=RULES      # CI/CD policy gate (exit 2 on violation)
npx decoy-scan --verbose           # Show all tools including low-risk
npx decoy-scan --quiet             # Suppress status output (exit code only)
npx decoy-scan --no-color          # Disable colored output
```

Run from your project root to include project-level `.mcp.json` configs.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high-risk issues |
| `1` | High-risk issues found |
| `2` | Critical issues, tool poisoning, toxic flows, or policy violation |

## Library

```javascript
import {
  scan,
  toSarif,
  classifyTool,
  detectPoisoning,
  analyzeToxicFlows,
  hashToolManifest,
  detectManifestChanges,
  discoverSkills,
  analyzeSkill,
} from 'decoy-scan';

const results = await scan({ skills: true });
console.log(results.toxicFlows);    // [{ id: "TF001", severity: "critical", roles: {...} }]
console.log(results.skills);        // [{ name: "...", findings: [...] }]
console.log(results.servers[0].manifestHash);  // "45c4c571f03c78a2"
```

## How It Compares

| | decoy-scan | Snyk agent-scan |
|---|---|---|
| Language | JavaScript | Python |
| Dependencies | **0** | 15 (aiohttp, pydantic, mcp, etc.) |
| Install | `npx decoy-scan` | `uvx snyk-agent-scan` + Snyk account |
| Cloud required | **No** | Yes (sends data to Snyk API) |
| Toxic flow analysis | **Yes (local)** | Yes (cloud) |
| Manifest change detection | **Yes** | Yes (registry-based) |
| Skill scanning | **Yes** | Yes |
| CI/CD policy gate | **Yes** | No |
| SARIF output | **Yes** | No |
| OWASP mapping | **Yes** | No |
| Hosts supported | **8** | 6 |
| Tripwire integration | **Yes (decoy-mcp)** | No |

## Supported Hosts

Claude Desktop, Cursor, Windsurf, VS Code, Claude Code (global + project), Zed, Cline

## Related

- [decoy-mcp](https://npmjs.com/package/decoy-mcp) — Tripwire tools that detect when agents are compromised
- [Decoy Guard](https://decoy.run) — Dashboard, threat intel, compliance reports
- [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## License

MIT
