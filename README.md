<p align="center">
  <a href="https://decoy.run?utm_source=github&utm_medium=scan_readme" target="_blank" rel="noopener noreferrer">
    <img alt="Decoy Scan" src="https://raw.githubusercontent.com/decoy-run/decoy-scan/main/.github/assets/hero.jpg" width="800">
  </a>
</p>
<h1 align="center">
  Decoy Scan
</h1>

<p align="center">
  <a href="https://www.npmjs.com/package/decoy-scan"><img alt="npm" src="https://img.shields.io/npm/v/decoy-scan?color=111827&labelColor=111827"></a>
  <a href="https://decoy.run/docs?utm_source=github&utm_medium=scan_readme"><img alt="documentation" src="https://img.shields.io/badge/documentation-decoy-111827?labelColor=111827"></a>
  <a href="https://decoy.run/changelog?utm_source=github&utm_medium=scan_readme"><img alt="changelog" src="https://img.shields.io/badge/changelog-latest-111827?labelColor=111827"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-111827?labelColor=111827"></a>
</p>

Find security risks in your MCP servers before attackers do. Zero dependencies, zero config, zero account required.

Scans Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, and Cline. Finds risky tools, detects prompt injection, analyzes toxic data flows, tracks manifest changes, and maps everything to the OWASP Agentic Top 10.

**Works with:** Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, Cline

## 🚀 Get Started

```bash
npx decoy-scan
```

That's it. No install, no account, no config. Runs against every MCP host it finds on the machine and prints the risk picture.

## 🧑‍💻 Install

No install required — run directly with `npx`. Requires Node.js 18+.

Or pin it in CI:

```yaml
- uses: decoy-run/decoy-scan@v1
  with:
    policy: no-critical,no-poisoning,no-toxic-flows
    report: true
    token: ${{ secrets.DECOY_TOKEN }}
```

## 🎓 Docs

- [Overview](https://decoy.run/docs/scan/overview)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## 🔍 What it checks

| Check | What it finds |
|-------|---------------|
| Tool risk classification | Critical/high/medium/low tools by name + description |
| Prompt injection detection | 37 patterns across 20 attack categories in tool descriptions |
| Toxic flow analysis | Cross-server data leak (TF001) and destructive (TF002) attack chains |
| Tool manifest hashing | Tool additions, removals, and description changes between scans |
| Skill scanning | Prompt injection, hardcoded secrets, suspicious URLs in Claude Code skills |
| Server command analysis | Pipe-to-shell, inline code, typosquatting, temp directory spawning |
| Environment variable exposure | API keys, tokens, secrets, cloud credentials passed to servers |
| Supply chain advisories | 40+ known vulnerable MCP packages via Decoy advisory database |
| Transport security | HTTP without TLS, missing auth, wildcard CORS, public-bound SSE |
| Input sanitization | Unconstrained parameters, missing maxLength, open schemas |
| Permission scope | Over-privileged servers, dangerous capability combinations |
| OWASP mapping | Every finding mapped to ASI01–ASI05 |

## 🤖 GitHub Action

One step. Scans MCP configs, enforces policy, uploads results to GitHub Security tab.

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: decoy-run/decoy-scan@v1
```

Fails the build on critical tools or prompt injection. Results appear in the Security tab.

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `policy` | `no-critical,no-poisoning` | Comma-separated policy rules |
| `sarif` | `true` | Upload SARIF to GitHub Security tab |
| `report` | `false` | Upload to Decoy Guard dashboard |
| `token` | — | Decoy API token (for `report`) |
| `verbose` | `false` | Show all tools including low-risk |

### Policy rules

```
no-critical          Fail on critical tools (code exec, file write)
no-high              Fail on high-risk tools (file read, network)
no-poisoning         Fail on prompt injection in tool descriptions
no-toxic-flows       Fail on cross-server data leak / destructive chains
no-secrets           Fail on secrets exposed in MCP config
require-tripwires    Fail if decoy-tripwire not installed
max-critical=N       Fail if more than N critical tools
max-high=N           Fail if more than N high-risk tools
```

### Manual CI/CD

If you prefer raw commands over the Action:

```yaml
- run: npx decoy-scan --policy=no-critical,no-poisoning
- run: npx decoy-scan --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## 🛠 Options

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

## 💡 Explain

Ask the scanner why something was flagged, what a tier means, or what a finding category is looking for:

```bash
npx decoy-scan explain critical          # What "critical" means + what to do
npx decoy-scan explain tool-description  # What a finding category checks
npx decoy-scan explain prompt-override   # What a poisoning type looks like
npx decoy-scan explain evaluate_script   # Why a tool was classified the way it was
npx decoy-scan explain list              # Everything you can explain
npx decoy-scan explain critical --json   # Structured output for agents
```

Explanations resolve against the same patterns the scanner uses, so they can't drift. `--json` works on every path and is designed for agent consumption in Claude Code, Cursor, and anything else with shell access.

Run from your project root to include project-level `.mcp.json` configs.

## 🏁 Exit codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high-risk issues |
| `1` | High-risk issues found |
| `2` | Critical issues, tool poisoning, toxic flows, or policy violation |

## 📚 Library

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

## ⚖ How it compares

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
| Tripwire integration | **Yes (decoy-tripwire)** | No |

## 🚢 Release Notes

See [CHANGELOG.md](CHANGELOG.md) or the [hosted changelog](https://decoy.run/changelog).

## 🤝 Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) if present.

## 🔗 Related

- [decoy-tripwire](https://npmjs.com/package/decoy-tripwire) — Tripwire tools that detect when agents are compromised
- [decoy-redteam](https://npmjs.com/package/decoy-redteam) — Autonomous red team for MCP servers
- [Decoy Guard](https://decoy.run) — Dashboard, threat intel, compliance reports

## 📝 License

MIT — see [LICENSE](LICENSE).
