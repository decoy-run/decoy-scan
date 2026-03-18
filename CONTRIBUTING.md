# Contributing to decoy-scan

Thanks for your interest in improving MCP security.

## Development

```bash
git clone https://github.com/decoy-run/decoy-scan
cd decoy-scan
node bin/cli.mjs --help
```

No build step. No dependencies to install. Just Node.js >= 18.

## Code Structure

Everything is in `index.mjs`:

| Section | What it does |
|---------|-------------|
| `RISK_PATTERNS` + `classifyTool()` | Tool risk classification by name/description |
| `POISONING_PATTERNS` + `detectPoisoning()` | Prompt injection detection in tool descriptions |
| `analyzeServerCommand()` | Server spawn command analysis |
| `SENSITIVE_ENV_PATTERNS` + `analyzeEnvExposure()` | Environment variable exposure |
| `analyzeReadiness()` | Production readiness heuristics |
| `OWASP_MAP` + `mapToOwasp()` | OWASP Agentic Top 10 mapping |
| `HOST_CONFIGS` + `discoverConfigs()` | MCP client config discovery |
| `probeServer()` | MCP stdio probing |
| `scan()` | Full scan orchestrator |
| `toSarif()` | SARIF output generator |

## Adding Poisoning Patterns

Poisoning detection patterns live in `POISONING_PATTERNS` in `index.mjs`. Each pattern has:

```javascript
{
  pattern: /regex/i,           // What to match
  type: "category-name",       // Finding type (used for OWASP mapping)
  severity: "critical",        // critical, high, medium, low
  description: "Human-readable" // Shown in output
}
```

After adding a pattern, add its `type` to `OWASP_MAP` if applicable.

## Adding Host Configs

To support a new MCP client, add an entry to `HOST_CONFIGS`:

```javascript
"New Client": () => {
  const p = platform();
  if (p === "darwin") return join(homedir(), "path", "to", "config.json");
  if (p === "win32") return join(process.env.APPDATA || "", "path", "config.json");
  return join(homedir(), ".config", "path", "config.json");
},
```

## Adding Readiness Checks

Readiness heuristics live in `analyzeReadiness()`. Follow the pattern:

```javascript
if (/* condition */) {
  findings.push({
    type: "readiness-check-name",
    severity: "medium",
    description: "What's wrong and why it matters"
  });
}
```

## Testing

```bash
node bin/cli.mjs --no-probe              # Config-only
node bin/cli.mjs --no-advisories         # Skip network calls
node bin/cli.mjs --json                  # Verify JSON structure
node bin/cli.mjs --sarif                 # Verify SARIF structure
node bin/cli.mjs --verbose               # Show everything
```

## Submitting Changes

1. Fork the repo
2. Create a branch (`git checkout -b add-new-pattern`)
3. Make your changes
4. Test locally with all output modes
5. Open a PR with a clear description

## Design Principles

- **Zero dependencies.** Node.js builtins only. Don't add npm packages.
- **No build step.** Raw ES modules. No TypeScript, no bundler.
- **Fast.** Scan should complete in seconds. Timeout servers aggressively.
- **Safe.** Never modify configs. Read-only scanning. Kill spawned servers promptly.
- **Agent-first.** JSON and SARIF output must be machine-parseable. AGENTS.md must be comprehensive.

## Reporting Security Issues

Email agent@decoy.run for security vulnerabilities. Do not open public issues for security bugs.
