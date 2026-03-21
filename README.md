# decoy-scan

Security scanner for MCP server configurations. Like `npm audit`, but for your AI agent tool servers.

Scans Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, and Cline. Finds risky tools, detects tool poisoning, validates input sanitization, checks SSE transport security, scores permission scope, and maps everything to the OWASP Agentic Top 10. No account required.

<!-- Demo: npx decoy-scan output -->
![decoy-scan demo](https://res.cloudinary.com/dohqjvu9k/image/upload/v1/decoy-scan-demo.gif)

## Quick Start

```bash
npx decoy-scan
```

No signup, no config, no dependencies.

## What It Checks

### Tool Risk Classification
Every tool exposed by your MCP servers is classified by name and description analysis:
- **Critical**: `execute_command`, `write_file`, `make_payment`, `modify_dns`, `delete_*`, `eval`, `spawn`
- **High**: `read_file`, `http_request`, `database_query`, `access_credentials`, `send_email`, `install_package`
- **Medium**: `list_dir`, `search`, `upload`, `download`, `git_*`, `browse`, `screenshot`
- **Low**: Everything else

### Tool Poisoning Detection
Scans tool descriptions for hidden prompt injection — the attack vector behind [OWASP ASI01 (Agent Goal Hijacking)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):
- Instruction override attempts ("ignore previous instructions")
- Behavior injection ("you must also call...")
- Concealment patterns ("do not tell the user")
- Cross-tool references (tool shadowing)
- Role/conversation injection (`[SYSTEM]`, `assistant:`)
- Invisible Unicode characters
- Excessively long descriptions (injection hiding)

### Server Command Analysis
Checks if the MCP server spawn command itself is suspicious:
- Running from `/tmp` or temp directories
- Pipe-to-shell patterns (`curl | sh`)
- Inline code execution (`python -c`, `node -e`)
- Network tools as server commands (`nc`, `socat`)
- Base64-encoded arguments
- Potential npm typosquatting

### Environment Variable Exposure
Flags when sensitive credentials are passed to MCP servers via env config:
- API keys, tokens, secrets, passwords
- Database connection strings
- Cloud credentials (AWS, GCP)
- Service credentials (Stripe, OpenAI, Anthropic, GitHub)

### Supply Chain Advisories
Cross-references installed MCP servers against the [Decoy advisory database](https://app.decoy.run/monitor/mcp) — known vulnerabilities in 40+ MCP server packages and AI agent frameworks.

### Transport Security (SSE)
Checks for insecure Server-Sent Events configurations:
- HTTP without TLS (credentials in plaintext)
- Missing authentication on SSE endpoints
- Wildcard CORS origins
- Servers bound to all interfaces (0.0.0.0)
- Missing rate limiting

### Input Sanitization Validation
Validates that tool schemas properly constrain inputs:
- Parameters without type constraints
- Unconstrained dangerous parameters (`command`, `query`, `path`, `url`)
- Missing `maxLength` on string inputs for high-risk tools
- Open object/array parameters without item or property constraints
- Schemas allowing `additionalProperties` on critical tools

### Permission Scope Analysis
Scores the aggregate capability scope across all tools in a server:
- Over-privileged servers with 4+ capability domains
- Dangerous combinations: shell execution + network access (RCE chains)
- Dangerous combinations: credential access + network access (exfiltration chains)
- Dangerous combinations: file write + shell execution (persistent execution)

### OWASP Agentic Top 10 Mapping
Every finding is mapped to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):
- **ASI01** — Agent Goal Hijacking (tool poisoning, prompt injection)
- **ASI02** — Unsafe Tool Use (critical/high-risk tools, input sanitization, permission scope)
- **ASI03** — Supply Chain Risk (typosquatting, env exposure, vulnerable packages, transport security)
- **ASI05** — Cascading Failures (forced tool chaining)

## Example Output

```
decoy-scan — MCP Supply Chain Security Scanner

  Found configs: Claude Desktop, Cursor, Claude Code
  Probing servers...

  ■ my-server  (Claude Desktop, Cursor)
    POISONING Tool description attempts to override agent instructions (execute_command)
    ENV       Passes api-key to server via env var "OPENAI_API_KEY"
    CRITICAL  execute_command
    HIGH      read_file
    + 3 low-risk tools

  ○ memory  (Claude Desktop)
    + 4 low-risk tools

  OWASP Agentic Top 10

  ASI01  Agent Goal Hijacking  (1 finding)
  ASI02  Unsafe Tool Use  (2 findings)
  ASI03  Supply Chain Risk  (1 finding)

  Summary
  2 servers scanned
  1 critical
  1 tool poisoning finding
  1 env exposure

  ✗ Issues found
```

## Options

```bash
npx decoy-scan                  # Full scan with server probing
npx decoy-scan --no-probe       # Config-only (don't spawn servers)
npx decoy-scan --no-advisories  # Skip advisory database check
npx decoy-scan --verbose        # Show all tools including low-risk
npx decoy-scan --json           # JSON output
npx decoy-scan --sarif          # SARIF output (GitHub Security, VS Code)
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high-risk issues |
| `1` | High-risk issues found |
| `2` | Critical issues or tool poisoning found |

## CI/CD Integration

SARIF output plugs directly into GitHub Code Scanning. All findings include OWASP tags for compliance filtering.

```yaml
# .github/workflows/mcp-scan.yml
- name: Scan MCP servers
  run: npx decoy-scan --sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Library

```javascript
import { scan, toSarif, classifyTool, detectPoisoning, analyzeServerCommand, analyzeTransport, analyzeInputSanitization, analyzePermissionScope } from 'decoy-scan';

const results = await scan();
console.log(results.summary);
// { total: 5, critical: 1, high: 2, ..., poisoned: 1, envExposures: 2 }

console.log(results.owasp);
// { ASI01: { name: "Agent Goal Hijacking", count: 1 }, ASI02: { ... } }
```

## How It Compares

| | decoy-scan | mcp-scan (Snyk) | Cisco MCP Scanner |
|---|---|---|---|
| Language | JavaScript | Python | Python |
| Dependencies | **0** | pip install | pip install |
| Install | `npx decoy-scan` | `pip install mcp-scan` | `pip install mcp-scanner` |
| Tool risk classification | Name + description regex | Prompt injection probes | YARA + LLM-as-judge |
| Tool poisoning detection | **37 patterns, 20 categories** | Yes (LLM-based) | Yes (LLM-based) |
| Server command analysis | Yes | No | No |
| Env exposure detection | Yes | No | No |
| SSE transport security | Yes | No | No |
| Input sanitization validation | Yes | No | No |
| Permission scope analysis | Yes | No | No |
| OWASP mapping | Yes (ASI01-05) | No | No |
| Advisory database | Yes (Decoy) | No | Yes (Cisco AI Defense) |
| SARIF output | Yes | No | No |
| Hosts supported | **8** | 3 | 3 |

## Supported Hosts

- Claude Desktop (macOS, Windows, Linux)
- Cursor
- Windsurf
- VS Code
- Claude Code (global + project `.mcp.json`)
- Zed
- Cline

## Related

- [decoy-mcp](https://npmjs.com/package/decoy-mcp) — Tripwire MCP tools that detect prompt injection attacks in real time
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Decoy threat intelligence](https://app.decoy.run/monitor/stats) — Public threat feed for AI agent security

## License

MIT
