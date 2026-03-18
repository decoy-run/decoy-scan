#!/usr/bin/env node

// decoy-scan CLI — scan MCP server configs for security risks
// Usage:
//   npx decoy-scan              — scan all MCP configs
//   npx decoy-scan --no-probe   — skip server probing (config-only)
//   npx decoy-scan --sarif      — SARIF output for CI/CD
//   npx decoy-scan --json       — JSON output

import { scan, toSarif, discoverConfigs } from "../index.mjs";

const args = process.argv.slice(2);
const jsonMode = args.includes("--json");
const sarifMode = args.includes("--sarif");
const noProbe = args.includes("--no-probe");
const noAdvisories = args.includes("--no-advisories");
const helpMode = args.includes("--help") || args.includes("-h");
const versionMode = args.includes("--version") || args.includes("-V");
const verboseMode = args.includes("--verbose") || args.includes("-v");

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const ORANGE = "\x1b[38;5;208m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";
const RESET = "\x1b[0m";

const RISK_COLORS = { critical: RED, high: ORANGE, medium: YELLOW, low: DIM };
const RISK_ICONS = { critical: "■", high: "▲", medium: "●", low: "○" };

if (versionMode) {
  console.log("decoy-scan 0.1.0");
  process.exit(0);
}

if (helpMode) {
  console.log(`
${BOLD}decoy-scan${RESET} — MCP Supply Chain Security Scanner

${BOLD}Usage:${RESET}
  npx decoy-scan                Scan all MCP server configurations
  npx decoy-scan --no-probe     Config-only scan (don't spawn servers)
  npx decoy-scan --no-advisories  Skip advisory database check
  npx decoy-scan --json         JSON output
  npx decoy-scan --sarif        SARIF output (for GitHub Security, VS Code)
  npx decoy-scan --verbose      Show all tools including low-risk

${BOLD}What it scans:${RESET}
  Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, Cline

${BOLD}What it checks:${RESET}
  • Tool risk classification (critical/high/medium/low)
  • Tool poisoning detection (prompt injection in descriptions)
  • Server command analysis (suspicious spawn commands)
  • Environment variable exposure (secrets passed to servers)
  • Known vulnerable packages (via Decoy advisory database)
  • OWASP Agentic Top 10 mapping

${BOLD}Exit codes:${RESET}
  0  No critical or high-risk issues
  1  High-risk issues found
  2  Critical issues found

${BOLD}Links:${RESET}
  GitHub: https://github.com/decoy-run/decoy-scan
  npm:    https://npmjs.com/package/decoy-scan
`);
  process.exit(0);
}

async function main() {
  if (!jsonMode && !sarifMode) {
    console.log(`\n${BOLD}decoy-scan${RESET} — MCP Supply Chain Security Scanner\n`);
  }

  // Discovery phase
  const configs = discoverConfigs();
  if (configs.length === 0) {
    if (jsonMode) {
      console.log(JSON.stringify({ error: "No MCP configurations found", hosts: [] }));
    } else if (!sarifMode) {
      console.log(`  ${YELLOW}No MCP configurations found.${RESET}`);
      console.log(`  ${DIM}Install an MCP-compatible client (Claude Desktop, Cursor, etc.) first.${RESET}\n`);
    }
    process.exit(0);
  }

  if (!jsonMode && !sarifMode) {
    console.log(`  ${DIM}Found configs:${RESET} ${configs.map(c => c.host).join(", ")}`);
    console.log(`  ${DIM}${noProbe ? "Config-only scan (skipping server probes)" : "Probing servers..."}${RESET}\n`);
  }

  const results = await scan({ probe: !noProbe, advisories: !noAdvisories });

  if (sarifMode) {
    console.log(JSON.stringify(toSarif(results), null, 2));
    process.exit(0);
  }

  if (jsonMode) {
    console.log(JSON.stringify(results, null, 2));
    process.exit(0);
  }

  // Pretty print
  for (const server of results.servers) {
    const riskColor = RISK_COLORS[server.risk] || DIM;
    const icon = RISK_ICONS[server.risk] || "○";
    const hostStr = server.hosts.join(", ");

    console.log(`  ${riskColor}${icon}${RESET} ${BOLD}${server.name}${RESET}  ${DIM}(${hostStr})${RESET}`);

    if (server.error) {
      console.log(`    ${RED}Error: ${server.error}${RESET}`);
    }

    // Show findings (poisoning, command issues, env exposure)
    for (const f of server.findings) {
      const fc = RISK_COLORS[f.severity] || DIM;
      const label = f.source === "tool-description" ? "POISONING" :
                    f.source === "server-command" ? "COMMAND" :
                    f.source === "env-config" ? "ENV" :
                    f.source === "tool-count" ? "SURFACE" :
                    f.source === "readiness" ? "READINESS" : "FINDING";
      console.log(`    ${fc}${label.padEnd(9)}${RESET} ${f.description}${f.tool ? ` ${DIM}(${f.tool})${RESET}` : ""}`);
    }

    // Show risky tools (skip low unless verbose)
    const riskyTools = server.tools.filter(t => t.risk !== "low");
    const lowCount = server.tools.length - riskyTools.length;
    const toolsToShow = verboseMode ? server.tools : riskyTools;

    for (const tool of toolsToShow) {
      const tc = RISK_COLORS[tool.risk] || DIM;
      console.log(`    ${tc}${tool.risk.toUpperCase().padEnd(9)}${RESET}${tool.name}`);
      if (tool.description && verboseMode) {
        console.log(`              ${DIM}${tool.description.slice(0, 80)}${RESET}`);
      }
    }

    if (!verboseMode && lowCount > 0) {
      console.log(`    ${DIM}+ ${lowCount} low-risk tool${lowCount > 1 ? "s" : ""}${RESET}`);
    }

    if (server.tools.length === 0 && !server.error) {
      console.log(`    ${DIM}No tools discovered${RESET}`);
    }

    console.log();
  }

  // Advisories
  if (results.advisories.length > 0) {
    console.log(`  ${RED}${BOLD}Supply Chain Advisories${RESET}\n`);
    for (const adv of results.advisories) {
      console.log(`  ${RED}■${RESET} ${BOLD}${adv.title}${RESET}`);
      console.log(`    Server: ${adv.server}`);
      if (adv.affectedPackages) console.log(`    Package: ${adv.affectedPackages.join(", ")}`);
      if (adv.remediation) console.log(`    Fix: ${adv.remediation}`);
      if (adv.sourceUrl) console.log(`    ${DIM}${adv.sourceUrl}${RESET}`);
      console.log();
    }
  }

  // OWASP mapping
  const owaspEntries = Object.entries(results.owasp || {});
  if (owaspEntries.length > 0) {
    console.log(`  ${MAGENTA}${BOLD}OWASP Agentic Top 10${RESET}\n`);
    for (const [id, entry] of owaspEntries.sort((a, b) => a[0].localeCompare(b[0]))) {
      console.log(`  ${MAGENTA}${id}${RESET}  ${entry.name}  ${DIM}(${entry.count} finding${entry.count > 1 ? "s" : ""})${RESET}`);
    }
    console.log();
  }

  // Summary
  const s = results.summary;
  console.log(`  ${BOLD}Summary${RESET}`);
  console.log(`  ${s.total} server${s.total !== 1 ? "s" : ""} scanned`);
  if (s.critical > 0) console.log(`  ${RED}${s.critical} critical${RESET}`);
  if (s.high > 0) console.log(`  ${ORANGE}${s.high} high${RESET}`);
  if (s.medium > 0) console.log(`  ${YELLOW}${s.medium} medium${RESET}`);
  if (s.errors > 0) console.log(`  ${RED}${s.errors} error${s.errors !== 1 ? "s" : ""}${RESET}`);
  if (s.poisoned > 0) console.log(`  ${RED}${s.poisoned} tool poisoning finding${s.poisoned !== 1 ? "s" : ""}${RESET}`);
  if (s.suspicious > 0) console.log(`  ${ORANGE}${s.suspicious} suspicious command${s.suspicious !== 1 ? "s" : ""}${RESET}`);
  if (s.envExposures > 0) console.log(`  ${ORANGE}${s.envExposures} env exposure${s.envExposures !== 1 ? "s" : ""}${RESET}`);
  if (s.readiness > 0) console.log(`  ${YELLOW}${s.readiness} readiness issue${s.readiness !== 1 ? "s" : ""}${RESET}`);
  if (results.advisories.length > 0) console.log(`  ${RED}${results.advisories.length} advisory match${results.advisories.length !== 1 ? "es" : ""}${RESET}`);

  const exit = s.critical > 0 || s.poisoned > 0 ? 2 : s.high > 0 ? 1 : 0;
  console.log(`\n  ${exit === 0 ? GREEN + "✓ No critical issues" : RED + "✗ Issues found"}${RESET}\n`);
  process.exit(exit);
}

main().catch(e => {
  console.error(`Error: ${e.message}`);
  process.exit(1);
});
