#!/usr/bin/env node

// decoy-scan CLI — MCP supply chain security scanner

import { scan, toSarif, discoverConfigs } from "../index.mjs";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

// ─── Version ───

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8"));
const VERSION = PKG.version;

// ─── Args ───

const args = process.argv.slice(2);
const jsonMode = args.includes("--json");
const sarifMode = args.includes("--sarif");
const noProbe = args.includes("--no-probe");
const noAdvisories = args.includes("--no-advisories");
const helpMode = args.includes("--help") || args.includes("-h");
const versionMode = args.includes("--version") || args.includes("-V");
const verboseMode = args.includes("--verbose") || args.includes("-v");
const quietMode = args.includes("--quiet") || args.includes("-q");
const reportMode = args.includes("--report");
const briefMode = args.includes("--brief");
const shareMode = args.includes("--share");
const fixMode = args.includes("--fix");
const skillsMode = args.includes("--skills");
const yesMode = args.includes("--yes") || args.includes("-y");
const policyArg = args.find(a => a.startsWith("--policy="))?.split("=")[1];
const tokenArg = args.find(a => a.startsWith("--token="))?.split("=")[1] || process.env.DECOY_TOKEN;

// ─── Flag conflicts ───

if (jsonMode && sarifMode) {
  process.stderr.write("error: --json and --sarif are mutually exclusive\n");
  process.exit(1);
}

if (verboseMode && quietMode) {
  process.stderr.write("error: --verbose and --quiet are mutually exclusive\n");
  process.exit(1);
}

// ─── Color support ───

const isTTY = process.stderr.isTTY;
const noColor = args.includes("--no-color") ||
  "NO_COLOR" in process.env ||
  process.env.TERM === "dumb" ||
  (!isTTY && !process.env.FORCE_COLOR);

const c = noColor
  ? { bold: "", dim: "", red: "", green: "", yellow: "", orange: "", cyan: "", magenta: "", white: "", underline: "", reset: "" }
  : {
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    orange: "\x1b[38;5;208m",
    cyan: "\x1b[36m",
    magenta: "\x1b[35m",
    white: "\x1b[37m",
    underline: "\x1b[4m",
    reset: "\x1b[0m",
  };

// 3-tier color: red (act now), yellow (warning), default (info).
const RISK_COLORS = { critical: c.red, high: c.red, medium: c.yellow, low: "" };
const RISK_ICONS = { critical: "✗", high: "!", medium: "~", low: " " };

// ─── Output helpers ───

function status(msg) {
  if (!quietMode) process.stderr.write(msg + "\n");
}

function data(msg) {
  process.stdout.write(msg + "\n");
}

// ─── Spinner ───

function spinner(label) {
  if (!isTTY || quietMode) return { stop() {} };
  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  let i = 0;
  const id = setInterval(() => {
    process.stderr.write(`\r  ${c.dim}${frames[i++ % frames.length]} ${label}${c.reset}`);
  }, 80);
  return {
    stop(finalMsg) {
      clearInterval(id);
      process.stderr.write("\r\x1b[K");
      if (finalMsg) status(finalMsg);
    },
  };
}

// ─── Version ───

if (versionMode) {
  data(`decoy-scan ${VERSION}`);
  process.exit(0);
}

// ─── Help ───

if (helpMode) {
  data(`${c.bold}decoy-scan${c.reset}
Find security risks in your MCP servers before attackers do.

${c.bold}Usage:${c.reset}
  decoy-scan [flags]

${c.bold}Examples:${c.reset}
  npx decoy-scan                          Scan all MCP servers on this machine
  npx decoy-scan --json                   Machine-readable JSON output
  npx decoy-scan --json | jq '.summary'   Just the summary
  npx decoy-scan --sarif > scan.sarif     SARIF for GitHub Security tab
  npx decoy-scan --report --token=xxx     Upload results to Guard dashboard
  npx decoy-scan --verbose                Show all tools including low-risk
  npx decoy-scan --no-probe               Config-only scan (don't spawn servers)

${c.bold}Flags:${c.reset}
      --json              JSON output (stdout, pipeable to jq)
      --brief             Minimal JSON summary (for agents with limited context)
      --sarif             SARIF 2.1.0 output
      --no-probe          Config-only scan — don't spawn servers
      --no-advisories     Skip advisory database lookup
      --report            Upload results to Decoy dashboard
      --share             Generate a shareable public URL for results
      --skills            Scan Claude Code skills for injection and secrets
      --token string      API token (or set DECOY_TOKEN env var)
  -y, --yes               Skip confirmation prompts (for CI use)
  -v, --verbose           Show all tools including low-risk
  -q, --quiet             Suppress status output
      --no-color          Disable colored output
      --color             Force colored output
  -V, --version           Show version
  -h, --help              Show this help

${c.bold}Exit codes:${c.reset}
  0  No critical or high-risk issues
  1  High-risk issues found
  2  Critical issues or tool poisoning found

${c.bold}What it scans:${c.reset}
  Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, Cline
  Run from your project root to include project-level .mcp.json configs.

${c.bold}What it checks:${c.reset}
  Tool risk classification    Prompt injection / poisoning detection
  Server command analysis     Environment variable exposure
  Supply chain advisories     Transport security (SSE/HTTP)
  Input sanitization          Permission scope analysis
  Toxic flow detection        Tool manifest change detection
  Skill scanning (--skills)   OWASP Agentic Top 10 mapping

${c.bold}Agent integration:${c.reset}
  This CLI ships with AGENTS.md for AI agent reference.
  Use --json for structured output. Use --brief for minimal summaries.
`);
  process.exit(0);
}

// ─── Main ───

async function main() {
  const machineMode = jsonMode || sarifMode;

  if (!machineMode) {
    status("");
    status(`  ${c.bold}decoy-scan${c.reset} ${c.dim}v${VERSION}${c.reset}`);
  }

  // Discovery
  const configs = discoverConfigs();
  if (configs.length === 0) {
    if (briefMode && jsonMode) {
      data(JSON.stringify({ servers: 0, critical: 0, high: 0, medium: 0, low: 0, poisoned: 0, status: "pass" }));
      process.exit(0);
    }
    if (jsonMode) {
      data(JSON.stringify({
        tool: "decoy-scan",
        version: VERSION,
        timestamp: new Date().toISOString(),
        hosts: [],
        servers: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, errors: 0, poisoned: 0, suspicious: 0, envExposures: 0, toxicFlows: 0, manifestChanges: 0, skillIssues: 0 },
        advisories: [],
        toxicFlows: [],
        skills: [],
        owasp: [],
        error: "No MCP configurations found",
        hint: "Configure an MCP server in your IDE (Claude Desktop, Cursor, VS Code, etc.)\n  Docs: https://decoy.run/docs",
      }));
    } else if (sarifMode) {
      data(JSON.stringify({
        $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [{ tool: { driver: { name: "decoy-scan", version: VERSION, informationUri: "https://github.com/decoy-run/decoy-scan" } }, results: [] }],
      }));
    } else {
      status(`  ${c.yellow}No MCP configurations found.${c.reset}`);
      status(`  ${c.dim}Checked: Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, Cline${c.reset}`);
      status("");
      status(`  ${c.dim}Hint: Configure an MCP server in your IDE (Claude Desktop, Cursor, VS Code, etc.)\n  Docs: https://decoy.run/docs${c.reset}`);
    }
    process.exit(0);
  }

  if (!machineMode) {
    const hostNames = configs.map(h => h.host).join(", ");
    status(`  ${c.dim}Hosts:${c.reset} ${hostNames}`);
  }

  // Scan
  const sp = !machineMode
    ? spinner(noProbe ? "Scanning configs…" : "Probing servers…")
    : { stop() {} };

  const results = await scan({ probe: !noProbe, advisories: !noAdvisories, skills: skillsMode, configs });
  sp.stop();

  // #4: Explain what --no-probe misses
  if (noProbe && !machineMode) {
    status(`  ${c.dim}Config scan only — run without --no-probe to discover tools and get full analysis.${c.reset}`);
  }

  // Compute exit code based on severity (shared across all output modes)
  function computeExitCode(results) {
    const toolCounts = { critical: 0, high: 0 };
    for (const srv of results.servers) {
      if (srv.decoy) continue;
      for (const t of srv.tools) {
        if (t.risk === "critical") toolCounts.critical++;
        if (t.risk === "high") toolCounts.high++;
      }
    }
    const nonDecoyPoisoned = results.servers.filter(srv => !srv.decoy).reduce((n, srv) => n + srv.findings.filter(f => f.source === "tool-description").length, 0);
    const hasToxicFlows = results.toxicFlows?.length > 0;
    const hasSkillIssues = results.summary.skillIssues > 0;
    if (toolCounts.critical > 0 || nonDecoyPoisoned > 0 || hasToxicFlows) return 2;
    if (toolCounts.high > 0 || hasSkillIssues) return 1;
    return 0;
  }
  const scanExitCode = computeExitCode(results);

  // Machine output — #3: Add version/tool metadata to JSON
  if (sarifMode) {
    data(JSON.stringify(toSarif(results), null, 2));
    writeScanCache(results);
    process.exit(scanExitCode);
  }
  if (briefMode && jsonMode) {
    const s = results.summary;
    const nonDecoyServers = results.servers.filter(srv => !srv.decoy && !srv.error).length;
    const hasCritical = scanExitCode === 2;
    const hasHigh = scanExitCode === 1;
    data(JSON.stringify({
      servers: nonDecoyServers,
      critical: s.critical,
      high: s.high,
      medium: s.medium,
      low: s.low,
      poisoned: s.poisoned,
      status: hasCritical ? "fail" : hasHigh ? "warn" : "pass",
    }));
    writeScanCache(results);
    process.exit(scanExitCode);
  }
  if (jsonMode) {
    data(JSON.stringify({ tool: "decoy-scan", version: VERSION, ...results }, null, 2));
    writeScanCache(results);
    process.exit(scanExitCode);
  }

  // Quiet mode without machine output: exit silently with proper code
  if (quietMode) {
    writeScanCache(results);
    process.exit(scanExitCode);
  }

  // ─── Pretty output ───
  status("");

  const hasDecoy = results.servers.some(s => s.decoy);
  let hasDangerousTools = false;

  for (const server of results.servers) {
    // #1: Decoy tripwire server — show as active protection, not a threat
    if (server.decoy) {
      status(`  ${c.green}✓${c.reset} ${c.bold}${server.name}${c.reset}  ${c.dim}Tripwires active${c.reset}`);
      status("");
      continue;
    }

    const riskColor = RISK_COLORS[server.risk] || "";
    const icon = RISK_ICONS[server.risk] || " ";
    const hostStr = server.hosts.join(", ");

    status(`  ${riskColor}${icon}${c.reset} ${c.bold}${server.name}${c.reset}  ${c.dim}${hostStr}${c.reset}`);

    if (server.error) {
      status(`    ${c.red}Error: ${server.error}${c.reset}`);
      status(`    ${c.dim}Hint: Check the server command and ensure the binary is installed and on your PATH${c.reset}`);
    }

    if (!server.error) {
      // Tools — the most important thing. What can this server do?
      const criticalTools = server.tools.filter(t => t.risk === "critical");
      const highTools = server.tools.filter(t => t.risk === "high");
      const mediumTools = server.tools.filter(t => t.risk === "medium");
      const lowTools = server.tools.filter(t => t.risk === "low");

      if (criticalTools.length > 0 || highTools.length > 0) hasDangerousTools = true;

      if (criticalTools.length > 0) {
        status(`    ${c.red}${c.bold}${criticalTools.map(t => t.name).join(", ")}${c.reset}`);
      }
      if (highTools.length > 0) {
        status(`    ${c.red}${highTools.map(t => t.name).join(", ")}${c.reset}`);
      }
      if (mediumTools.length > 0 && verboseMode) {
        status(`    ${c.yellow}${mediumTools.map(t => t.name).join(", ")}${c.reset}`);
      }
      if (verboseMode && lowTools.length > 0) {
        status(`    ${lowTools.map(t => t.name).join(", ")}`);
      }

      // #8: Show medium and low counts separately
      if (!verboseMode) {
        const parts = [];
        if (mediumTools.length > 0) parts.push(`${mediumTools.length} medium`);
        if (lowTools.length > 0) parts.push(`${lowTools.length} low`);
        if (parts.length > 0) {
          status(`    ${c.dim}+ ${parts.join(", ")} risk${c.reset}`);
        }
      }

      if (server.tools.length === 0) {
        status(`    ${c.dim}No tools discovered${c.reset}`);
      }
    }

    // Findings — always shown, even for errored servers (static checks still run)
    const findings = server.findings;
    if (findings.length > 0) {
      const groups = {};
      for (const f of findings) {
        const key = f.source;
        if (!groups[key]) groups[key] = [];
        groups[key].push(f);
      }

      const categoryInfo = {
        "tool-description":   { label: "Prompt injection detected in tool descriptions", tier: "red",
                                fix: "Audit tool descriptions for hidden instructions — remove any text that overrides agent behavior" },
        "server-command":     { label: "Suspicious server spawn command", tier: "red",
                                fix: "Replace shell pipes with direct binary execution — avoid sh -c and eval patterns" },
        "transport":          { label: "Insecure transport (HTTP without TLS)", tier: "red",
                                fix: "Switch to HTTPS or use stdio transport — never send credentials over plain HTTP" },
        "env-config":         { label: "Secrets exposed via environment variables", tier: "yellow",
                                fix: "Move secrets to a .env file or vault — don't inline them in MCP config" },
        "tool-count":         { label: "Large attack surface", tier: "yellow",
                                fix: "Split into focused servers with fewer tools — limit blast radius per server" },
        "permission-scope":   { label: "Server has too many permissions", tier: "yellow",
                                fix: "Apply least-privilege — separate read-only and write servers" },
        "readiness":          { label: "Tools missing input constraints or safety checks", tier: "info",
                                fix: "Add inputSchema with descriptions, required fields, and type constraints" },
        "input-sanitization": { label: "Tools accept unconstrained input", tier: "info",
                                fix: "Add maxLength, pattern, or enum constraints to string parameters" },
        "manifest-change":    { label: "Tool manifest changed since last scan", tier: "yellow",
                                fix: "Review the diff — new tools may introduce unintended capabilities" },
      };

      const tierColor = { red: c.red, yellow: c.yellow, info: c.dim };

      for (const [source, items] of Object.entries(groups)) {
        const info = categoryInfo[source] || { label: source, tier: "info" };
        if (!verboseMode && info.tier === "info") continue;

        const color = tierColor[info.tier] || "";
        const count = items.length > 1 ? ` ${c.dim}(${items.length})${c.reset}` : "";
        status(`    ${color}${info.label}${c.reset}${count}`);
        if (info.fix) {
          status(`    ${c.dim}  → ${info.fix}${c.reset}`);
        }
      }
    }

    status("");
  }

  // Advisories
  if (results.advisories.length > 0) {
    status(`  ${c.red}${c.bold}Supply Chain Advisories${c.reset}`);
    status("");
    for (const adv of results.advisories) {
      status(`  ${c.red}✗${c.reset} ${c.bold}${adv.title}${c.reset}`);
      status(`    Server: ${adv.server}`);
      if (adv.affectedPackages) status(`    Package: ${adv.affectedPackages.join(", ")}`);
      if (adv.remediation) status(`    Fix: ${adv.remediation}`);
      if (adv.sourceUrl) status(`    ${c.dim}${adv.sourceUrl}${c.reset}`);
      status("");
    }
  }

  // Toxic flows
  if (results.toxicFlows?.length > 0) {
    status(`  ${c.red}${c.bold}Toxic Flows${c.reset}`);
    status("");
    for (const flow of results.toxicFlows) {
      status(`  ${c.red}✗${c.reset} ${c.bold}${flow.id}${c.reset} ${flow.description}`);
      for (const [role, tools] of Object.entries(flow.roles)) {
        status(`    ${c.dim}${role.replace(/_/g, " ")}:${c.reset} ${tools.join(", ")}`);
      }
      status("");
    }
  }

  // Skills
  if (results.skills?.length > 0) {
    const skillsWithIssues = results.skills.filter(s => s.findings.length > 0);
    if (skillsWithIssues.length > 0) {
      status(`  ${c.red}${c.bold}Skill Issues${c.reset}`);
      status("");
      for (const skill of skillsWithIssues) {
        status(`  ${c.red}!${c.reset} ${c.bold}${skill.name}${c.reset}  ${c.dim}${skill.source}/${skill.type}${c.reset}`);
        for (const f of skill.findings) {
          const fc = { critical: c.red, high: c.red, medium: c.yellow }[f.severity] || c.dim;
          status(`    ${fc}${f.description}${c.reset}`);
        }
        status("");
      }
    } else if (skillsMode) {
      status(`  ${c.green}✓${c.reset} ${results.skills.length} skill${results.skills.length !== 1 ? "s" : ""} scanned, no issues`);
      status("");
    }
  }

  if (hasDangerousTools) {
    status(`  ${c.dim}critical = code exec, file write, payments · high = file read, network, credentials${c.reset}`);
  }

  // #7: Summary uses tool-level counts, not server-level
  const toolCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const srv of results.servers) {
    if (srv.decoy) continue; // Don't count decoy tools in summary
    for (const t of srv.tools) toolCounts[t.risk]++;
  }
  const totalTools = toolCounts.critical + toolCounts.high + toolCounts.medium + toolCounts.low;
  const nonDecoyServers = results.servers.filter(s => !s.decoy);

  const s = results.summary;
  // Compute exit from non-decoy tool counts + poisoning + static config findings
  const nonDecoyPoisoned = results.servers.filter(srv => !srv.decoy).reduce((n, srv) => n + srv.findings.filter(f => f.source === "tool-description").length, 0);
  const hasToxicFlows = results.toxicFlows?.length > 0;
  const hasSkillIssues = results.summary.skillIssues > 0;
  // Static config findings (env exposure, pipe-to-shell, transport) affect exit code even on errored servers
  const staticCritical = results.servers.filter(srv => !srv.decoy).reduce((n, srv) => n + srv.findings.filter(f => f.severity === "critical").length, 0);
  const staticHigh = results.servers.filter(srv => !srv.decoy).reduce((n, srv) => n + srv.findings.filter(f => f.severity === "high").length, 0);
  const exit = toolCounts.critical > 0 || nonDecoyPoisoned > 0 || hasToxicFlows || staticCritical > 0 ? 2 : (toolCounts.high > 0 || staticHigh > 0 || hasSkillIssues) ? 1 : 0;

  status(`  ${c.dim}${"─".repeat(40)}${c.reset}`);

  if (exit === 0) {
    status(`  ${c.green}✓${c.reset} ${c.bold}Clean.${c.reset}  ${c.dim}${nonDecoyServers.length} server${nonDecoyServers.length !== 1 ? "s" : ""}, ${totalTools} tool${totalTools !== 1 ? "s" : ""} — no issues found${c.reset}`);
  } else {
    const parts = [];
    const totalCritical = toolCounts.critical + staticCritical;
    const totalHigh = toolCounts.high + staticHigh;
    if (totalCritical > 0) parts.push(`${c.red}${totalCritical} critical${c.reset}`);
    if (totalHigh > 0) parts.push(`${c.red}${totalHigh} high${c.reset}`);
    if (toolCounts.medium > 0) parts.push(`${c.yellow}${toolCounts.medium} warning${c.reset}`);
    if (s.poisoned > 0) parts.push(`${c.red}${s.poisoned} poisoned${c.reset}`);
    if (hasToxicFlows) parts.push(`${c.red}${results.toxicFlows.length} toxic flow${results.toxicFlows.length > 1 ? "s" : ""}${c.reset}`);
    if (s.skillIssues > 0) parts.push(`${c.red}${s.skillIssues} skill issue${s.skillIssues > 1 ? "s" : ""}${c.reset}`);
    status(`  ${c.red}✗${c.reset} ${parts.join(", ")}  ${c.dim}across ${nonDecoyServers.length} server${nonDecoyServers.length !== 1 ? "s" : ""}, ${totalTools} tool${totalTools !== 1 ? "s" : ""}${c.reset}`);
    status(`  ${c.dim}  Better to find it here than in prod.${c.reset}`);
  }

  // Upload
  if (reportMode) {
    if (!tokenArg) {
      status("");
      status(`  ${c.red}--report requires a token.${c.reset}`);
      status(`  ${c.dim}Hint: Pass --token=YOUR_TOKEN or set DECOY_TOKEN in your environment.${c.reset}`);
      status(`  ${c.dim}Sign up at https://app.decoy.run to get a token.${c.reset}`);
      status("");
      process.exit(1);
    }
    const sp = spinner("Uploading results…");
    try {
      const resp = await fetch("https://app.decoy.run/api/scan/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${tokenArg}` },
        body: JSON.stringify({ results }),
      });
      const d = await resp.json();
      sp.stop();
      if (d.ok) {
        status(`  ${c.green}✓${c.reset} Uploaded ${c.dim}(score: ${d.score}/100)${c.reset}`);
        status(`  ${c.dim}${d.dashboardUrl}${c.reset}`);
      } else {
        status(`  ${c.red}Upload failed: ${d.error}${c.reset}`);
        status(`  ${c.dim}Hint: Check that your token is valid — regenerate at https://app.decoy.run/dashboard${c.reset}`);
      }
    } catch (e) {
      sp.stop();
      status(`  ${c.red}Upload failed: ${e.message}${c.reset}`);
      status(`  ${c.dim}Check your network connection and try again.${c.reset}`);
    }
  }

  // Next steps — context-aware based on whether decoy-tripwire is installed
  status("");
  if (exit !== 0) {
    if (hasDecoy) {
      status(`  ${c.dim}$${c.reset} npx decoy-tripwire watch    ${c.dim}# Watch triggers in real time${c.reset}`);
      status(`  ${c.dim}$${c.reset} npx decoy-tripwire status   ${c.dim}# Check recent triggers${c.reset}`);
      status(`  ${c.dim}$${c.reset} npx decoy-scan --report     ${c.dim}# Track over time in dashboard${c.reset}`);
    } else {
      status(`  ${c.dim}Scanning found the risk. Tripwires catch when it's exploited.${c.reset}`);
      status("");
      status(`  ${c.dim}$${c.reset} npx decoy-tripwire init     ${c.dim}# Install tripwires (2 min)${c.reset}`);
      status(`  ${c.dim}$${c.reset} npx decoy-scan --sarif      ${c.dim}# Export for CI/CD${c.reset}`);
      status(`  ${c.dim}$${c.reset} npx decoy-scan --report     ${c.dim}# Track over time in dashboard${c.reset}`);
    }
  } else {
    status(`  ${c.dim}$${c.reset} npx decoy-scan --report     ${c.dim}# Track over time in dashboard${c.reset}`);
  }

  // CI/CD policy gate
  let policyExit = exit;
  if (policyArg) {
    const policies = policyArg.split(",").map(p => p.trim());
    const violations = [];

    for (const policy of policies) {
      switch (policy) {
        case "no-critical":
          if (toolCounts.critical > 0) violations.push(`${toolCounts.critical} critical tool${toolCounts.critical > 1 ? "s" : ""} found`);
          break;
        case "no-high":
          if (toolCounts.high > 0) violations.push(`${toolCounts.high} high-risk tool${toolCounts.high > 1 ? "s" : ""} found`);
          break;
        case "no-toxic-flows":
          if (hasToxicFlows) violations.push(`${results.toxicFlows.length} toxic flow${results.toxicFlows.length > 1 ? "s" : ""} detected`);
          break;
        case "no-poisoning":
          if (nonDecoyPoisoned > 0) violations.push(`${nonDecoyPoisoned} tool poisoning finding${nonDecoyPoisoned > 1 ? "s" : ""}`);
          break;
        case "no-secrets":
          const secrets = results.servers.reduce((n, s) => n + s.findings.filter(f => f.source === "env-config").length, 0);
          if (secrets > 0) violations.push(`${secrets} exposed secret${secrets > 1 ? "s" : ""}`);
          break;
        case "require-tripwires": {
          const hasDecoyServer = results.servers.some(s => s.decoy);
          if (!hasDecoyServer) violations.push("No tripwires installed");
          break;
        }
        default:
          if (!policy.startsWith("max-")) {
            status(`  ${c.yellow}Unknown policy: ${policy}${c.reset}`);
          } else {
            // max-critical=0, max-high=5, etc.
            const [, level, maxStr] = policy.match(/^max-(\w+)=(\d+)$/) || [];
            const max = parseInt(maxStr);
            if (level && !isNaN(max)) {
              const count = level === "toxic-flows" ? (results.toxicFlows?.length || 0) : (toolCounts[level] || 0);
              if (count > max) violations.push(`${count} ${level} exceeds max ${max}`);
            }
          }
      }
    }

    if (violations.length > 0) {
      status("");
      status(`  ${c.red}Policy violations:${c.reset}`);
      for (const v of violations) status(`  ${c.red}✗${c.reset} ${v}`);
      policyExit = 2;
    } else {
      status("");
      status(`  ${c.green}✓${c.reset} All policies passed`);
    }
  }

  // --share: upload results and get a shareable public URL
  if (shareMode) {
    if (!yesMode) {
      const stdinIsTTY = process.stdin.isTTY;
      if (!stdinIsTTY) {
        process.stderr.write("error: --share requires --yes flag in non-interactive mode\n");
        process.exit(1);
      }
      process.stderr.write("Warning: --share uploads scan results (server names, tools, findings) to a public URL.\nContinue? [y/N] ");
      const answer = await new Promise(resolve => {
        process.stdin.setRawMode?.(false);
        process.stdin.resume();
        process.stdin.setEncoding("utf8");
        let buf = "";
        const timeout = setTimeout(() => { process.stdin.pause(); resolve(""); }, 30000);
        process.stdin.on("data", chunk => {
          buf += chunk;
          if (buf.includes("\n")) {
            clearTimeout(timeout);
            process.stdin.pause();
            resolve(buf.trim().toLowerCase());
          }
        });
      });
      if (answer !== "y" && answer !== "yes") {
        status("  Aborted.");
        process.exit(0);
      }
    }
    const sp = spinner("Generating shareable report…");
    try {
      const payload = {
        results: { ...results, tool: "decoy-scan", version: VERSION },
        timestamp: results.timestamp,
      };
      const resp = await fetch("https://app.decoy.run/api/share", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const d = await resp.json();
      sp.stop();
      if (d.url) {
        status(`  ${c.green}✓${c.reset} ${c.bold}${d.url}${c.reset}`);
        status(`  ${c.dim}Share this link — anyone can view the report.${c.reset}`);
      } else {
        status(`  ${c.red}Share failed: ${d.error || "unknown error"}${c.reset}`);
      }
    } catch (e) {
      sp.stop();
      status(`  ${c.red}Share failed: ${e.message}${c.reset}`);
    }
  }

  // --fix: detailed remediation plan per server
  if (fixMode) {
    const fixes = [];
    for (const server of results.servers) {
      if (server.decoy || server.error) continue;

      const critTools = server.tools.filter(t => t.risk === "critical");
      const highTools = server.tools.filter(t => t.risk === "high");

      // Tool-level fixes
      if (critTools.length > 0) {
        fixes.push({ server: server.name, severity: "critical",
          description: `${critTools.map(t => t.name).join(", ")} — add allowlist constraints or require user confirmation` });
      }
      if (highTools.length > 0) {
        fixes.push({ server: server.name, severity: "high",
          description: `${highTools.map(t => t.name).join(", ")} — restrict to read-only paths or scoped credentials` });
      }

      // Finding-level fixes
      for (const f of server.findings) {
        if (f.source === "tool-description") {
          fixes.push({ server: server.name, severity: "critical",
            description: `Prompt injection in tool descriptions — audit and remove hidden instructions` });
        }
        if (f.source === "env-config") {
          fixes.push({ server: server.name, severity: "high",
            description: `Move ${f.envVar || "secret"} to .env file or vault — don't inline in MCP config` });
        }
        if (f.source === "server-command") {
          fixes.push({ server: server.name, severity: "critical",
            description: `Replace shell command with direct binary path — avoid sh -c and eval` });
        }
        if (f.source === "transport") {
          fixes.push({ server: server.name, severity: "critical",
            description: `Switch to HTTPS or stdio transport — credentials are exposed over HTTP` });
        }
      }

      // Scope fix (once per server)
      if (server.findings.some(f => f.source === "permission-scope")) {
        fixes.push({ server: server.name, severity: "medium",
          description: `Split into separate read-only and write servers — limit blast radius` });
      }

      // Tripwire recommendation
      if (critTools.length > 0 && !results.servers.some(s => s.decoy)) {
        fixes.push({ server: server.name, severity: "info",
          description: `Install tripwires to detect exploitation: npx decoy-tripwire init` });
      }
    }

    // Deduplicate by description
    const seen = new Set();
    const unique = fixes.filter(f => {
      const key = `${f.server}:${f.description}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    if (unique.length > 0) {
      status("");
      status(`  ${c.bold}Remediation (${unique.length}):${c.reset}`);
      status("");
      const sevColor = { critical: c.red, high: c.orange || c.yellow, medium: c.yellow, info: c.dim };
      for (const fix of unique) {
        const fc = sevColor[fix.severity] || c.dim;
        status(`  ${fc}→${c.reset} ${c.dim}${fix.server}${c.reset}  ${fix.description}`);
      }
    } else {
      status("");
      status(`  ${c.green}✓${c.reset} Nothing to fix.`);
    }
  }

  // Write scan cache for decoy-tripwire exposure analysis
  writeScanCache(results);

  status("");
  process.exit(policyExit);
}

// Write scan results to ~/.decoy/scan.json for decoy-tripwire exposure analysis
const SCAN_CACHE_VERSION = 1;
function writeScanCache(results) {
  try {
    const cacheDir = join(homedir(), ".decoy");
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(join(cacheDir, "scan.json"), JSON.stringify({ version: SCAN_CACHE_VERSION, ...results }, null, 2) + "\n");
  } catch { /* Best-effort cache write — non-critical if ~/.decoy isn't writable */ }
}

main().catch(e => {
  status(`  ${c.red}error:${c.reset} ${e.message}`);
  if (verboseMode) status(`  ${c.dim}${e.stack}${c.reset}`);
  status(`  ${c.dim}Hint: Run with --verbose for full stack trace, or report at https://github.com/decoy-run/decoy-scan/issues${c.reset}`);
  process.exit(1);
});
