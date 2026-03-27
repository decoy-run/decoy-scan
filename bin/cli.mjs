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
const shareMode = args.includes("--share");
const fixMode = args.includes("--fix");
const skillsMode = args.includes("--skills");
const policyArg = args.find(a => a.startsWith("--policy="))?.split("=")[1];
const tokenArg = args.find(a => a.startsWith("--token="))?.split("=")[1] || process.env.DECOY_TOKEN;

// ─── Color support ───

const isTTY = process.stderr.isTTY;
const noColor = args.includes("--no-color") ||
  "NO_COLOR" in process.env ||
  process.env.TERM === "dumb" ||
  (!isTTY && !process.env.FORCE_COLOR);

const c = noColor
  ? { bold: "", dim: "", red: "", green: "", yellow: "", orange: "", cyan: "", magenta: "", reset: "" }
  : {
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    orange: "\x1b[38;5;208m",
    cyan: "\x1b[36m",
    magenta: "\x1b[35m",
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
      process.stderr.write("\r" + " ".repeat(label.length + 10) + "\r");
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
  decoy-scan                    Scan all MCP server configurations
  decoy-scan --no-probe         Config-only scan (skip server probing)
  decoy-scan --json | jq        Pipe structured output to jq
  decoy-scan --sarif > out.sarif Export for GitHub Security / VS Code
  decoy-scan --report           Upload results to Decoy dashboard

${c.bold}Flags:${c.reset}
      --json              JSON output (stdout, pipeable to jq)
      --sarif             SARIF 2.1.0 output
      --no-probe          Config-only scan — don't spawn servers
      --no-advisories     Skip advisory database lookup
      --report            Upload results to Decoy dashboard
      --skills            Scan Claude Code skills for injection and secrets
      --token string      API token (or set DECOY_TOKEN env var)
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
`);
  process.exit(0);
}

// ─── Main ───

async function main() {
  const machineMode = jsonMode || sarifMode;

  if (!machineMode) {
    status("");
    status(`  ${c.bold}decoy-scan${c.reset} ${c.dim}v${VERSION}${c.reset}`);
    status("");
  }

  // Discovery
  const configs = discoverConfigs();
  if (configs.length === 0) {
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
      status(`  ${c.dim}Install an MCP-compatible client first, then re-run.${c.reset}`);
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

  const results = await scan({ probe: !noProbe, advisories: !noAdvisories, skills: skillsMode });
  sp.stop();

  // #4: Explain what --no-probe misses
  if (noProbe && !machineMode) {
    status(`  ${c.dim}Config scan only — run without --no-probe to discover tools and get full analysis.${c.reset}`);
  }

  // Machine output — #3: Add version/tool metadata to JSON
  if (sarifMode) {
    data(JSON.stringify(toSarif(results), null, 2));
    writeScanCache(results);
    process.exit(0);
  }
  if (jsonMode) {
    data(JSON.stringify({ tool: "decoy-scan", version: VERSION, ...results }, null, 2));
    writeScanCache(results);
    process.exit(0);
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
      status("");
      continue;
    }

    // Tools — the most important thing. What can this server do?
    const criticalTools = server.tools.filter(t => t.risk === "critical");
    const highTools = server.tools.filter(t => t.risk === "high");
    const mediumTools = server.tools.filter(t => t.risk === "medium");
    const lowTools = server.tools.filter(t => t.risk === "low");

    if (criticalTools.length > 0 || highTools.length > 0) hasDangerousTools = true;

    if (criticalTools.length > 0) {
      status(`    ${c.red}${criticalTools.map(t => t.name).join(", ")}${c.reset}`);
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

    // Findings — collapsed by category with human-readable labels.
    const findings = server.findings;
    if (findings.length > 0) {
      const groups = {};
      for (const f of findings) {
        const key = f.source;
        if (!groups[key]) groups[key] = [];
        groups[key].push(f);
      }

      const categoryInfo = {
        "tool-description":   { label: "Prompt injection detected in tool descriptions", tier: "red" },
        "server-command":     { label: "Suspicious server spawn command", tier: "red" },
        "transport":          { label: "Insecure transport (HTTP without TLS)", tier: "red" },
        "env-config":         { label: "Secrets exposed via environment variables", tier: "yellow" },
        "tool-count":         { label: "Large attack surface", tier: "yellow" },
        "permission-scope":   { label: "Server has too many permissions", tier: "yellow" },
        "readiness":          { label: "Tools missing input constraints or safety checks", tier: "info" },
        "input-sanitization": { label: "Tools accept unconstrained input", tier: "info" },
        "manifest-change":    { label: "Tool manifest changed since last scan", tier: "yellow" },
      };

      const tierColor = { red: c.red, yellow: c.yellow, info: c.dim };

      for (const [source, items] of Object.entries(groups)) {
        const info = categoryInfo[source] || { label: source, tier: "info" };
        if (!verboseMode && info.tier === "info") continue;

        const color = tierColor[info.tier] || "";
        const count = items.length > 1 ? ` ${c.dim}(${items.length})${c.reset}` : "";
        status(`    ${color}${info.label}${c.reset}${count}`);
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

  // #6: Tool risk legend — show once if dangerous tools exist
  if (hasDangerousTools) {
    status(`  ${c.dim}Critical = code exec, file write, payments · High = file read, network, credentials${c.reset}`);
  }

  // #7: Summary uses tool-level counts, not server-level
  const toolCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const srv of results.servers) {
    if (srv.decoy) continue; // Don't count decoy tools in summary
    for (const t of srv.tools) toolCounts[t.risk]++;
  }
  const totalTools = toolCounts.critical + toolCounts.high + toolCounts.medium + toolCounts.low;
  const nonDecoyServers = results.servers.filter(s => !s.decoy && !s.error);

  const s = results.summary;
  // Compute exit from non-decoy tool counts + poisoning
  const nonDecoyPoisoned = results.servers.filter(srv => !srv.decoy).reduce((n, srv) => n + srv.findings.filter(f => f.source === "tool-description").length, 0);
  const hasToxicFlows = results.toxicFlows?.length > 0;
  const hasSkillIssues = results.summary.skillIssues > 0;
  const exit = toolCounts.critical > 0 || nonDecoyPoisoned > 0 || hasToxicFlows ? 2 : (toolCounts.high > 0 || hasSkillIssues) ? 1 : 0;

  status(`  ${c.dim}${"─".repeat(40)}${c.reset}`);
  status("");

  if (exit === 0) {
    status(`  ${c.green}✓${c.reset} ${c.bold}No issues found${c.reset}  ${c.dim}${nonDecoyServers.length} server${nonDecoyServers.length !== 1 ? "s" : ""}, ${totalTools} tools${c.reset}`);
  } else {
    const parts = [];
    if (toolCounts.critical > 0) parts.push(`${c.red}${toolCounts.critical} critical${c.reset}`);
    if (toolCounts.high > 0) parts.push(`${c.red}${toolCounts.high} high${c.reset}`);
    if (toolCounts.medium > 0) parts.push(`${c.yellow}${toolCounts.medium} warning${c.reset}`);
    if (s.poisoned > 0) parts.push(`${c.red}${s.poisoned} poisoned${c.reset}`);
    if (hasToxicFlows) parts.push(`${c.red}${results.toxicFlows.length} toxic flow${results.toxicFlows.length > 1 ? "s" : ""}${c.reset}`);
    if (s.skillIssues > 0) parts.push(`${c.red}${s.skillIssues} skill issue${s.skillIssues > 1 ? "s" : ""}${c.reset}`);
    status(`  ${c.red}✗${c.reset} ${c.bold}${parts.join(", ")}${c.reset}  ${c.dim}${nonDecoyServers.length} server${nonDecoyServers.length !== 1 ? "s" : ""}, ${totalTools} tools${c.reset}`);
  }

  // Upload
  if (reportMode) {
    if (!tokenArg) {
      status("");
      status(`  ${c.red}--report requires a token.${c.reset}`);
      status(`  ${c.dim}Pass --token=YOUR_TOKEN or set DECOY_TOKEN in your environment.${c.reset}`);
      status("");
      process.exit(1);
    }
    const sp = spinner("Uploading results…");
    try {
      const resp = await fetch("https://app.decoy.run/api/scan/upload?token=" + tokenArg, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ results }),
      });
      const d = await resp.json();
      sp.stop();
      if (d.ok) {
        status(`  ${c.green}✓${c.reset} Uploaded ${c.dim}(score: ${d.score}/100)${c.reset}`);
        status(`  ${c.dim}${d.dashboardUrl}${c.reset}`);
      } else {
        status(`  ${c.red}Upload failed: ${d.error}${c.reset}`);
      }
    } catch (e) {
      sp.stop();
      status(`  ${c.red}Upload failed: ${e.message}${c.reset}`);
      status(`  ${c.dim}Check your network connection and try again.${c.reset}`);
    }
  }

  // #5: Next steps — context-aware based on whether decoy-mcp is installed
  status("");
  if (exit !== 0) {
    if (hasDecoy) {
      // Decoy already installed — suggest monitoring, not re-installing
      status(`  ${c.bold}Next:${c.reset}`);
      status(`  ${c.dim}$${c.reset} npx decoy-mcp watch      ${c.dim}# Watch triggers in real time${c.reset}`);
      status(`  ${c.dim}$${c.reset} npx decoy-mcp status     ${c.dim}# Check recent triggers${c.reset}`);
      status(`  ${c.dim}$${c.reset} npx decoy-scan --report   ${c.dim}# Track over time in dashboard${c.reset}`);
    } else {
      status(`  ${c.bold}What now?${c.reset}`);
      status(`  Scanning found the risk. Tripwires detect when it's exploited.`);
      status("");
      status(`  ${c.dim}$${c.reset} npx decoy-mcp init       ${c.dim}# Install tripwires (2 min setup)${c.reset}`);
      status(`  ${c.dim}$${c.reset} npx decoy-scan --sarif    ${c.dim}# Export for CI/CD${c.reset}`);
      status(`  ${c.dim}$${c.reset} npx decoy-scan --report   ${c.dim}# Track over time in dashboard${c.reset}`);
    }
  } else {
    status(`  ${c.dim}$${c.reset} npx decoy-scan --report   ${c.dim}# Track over time in dashboard${c.reset}`);
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

  // --fix: generate hardened MCP config
  if (fixMode) {
    const fixes = [];
    for (const server of results.servers) {
      if (server.decoy || server.error) continue;
      for (const f of server.findings) {
        if (f.source === "env-config") {
          fixes.push({ server: server.name, type: "env", description: `Move ${f.envVar || "secret"} to a vault or .env file instead of MCP config` });
        }
        if (f.source === "permission-scope") {
          fixes.push({ server: server.name, type: "scope", description: `Server "${server.name}" has too many permissions — consider splitting into separate servers` });
          break;
        }
      }
      const critTools = server.tools.filter(t => t.risk === "critical");
      if (critTools.length > 0 && !results.servers.some(s => s.decoy)) {
        fixes.push({ server: server.name, type: "tripwire", description: `Install tripwires to detect attacks: npx decoy-mcp init` });
      }
    }

    if (fixes.length > 0) {
      status("");
      status(`  ${c.bold}Fixes (${fixes.length}):${c.reset}`);
      for (const fix of fixes) {
        status(`  ${c.green}→${c.reset} ${c.dim}[${fix.server}]${c.reset} ${fix.description}`);
      }
    } else {
      status("");
      status(`  ${c.green}✓${c.reset} No fixes needed`);
    }
  }

  // Write scan cache for decoy-mcp exposure analysis
  writeScanCache(results);

  status("");
  process.exit(policyExit);
}

// Write scan results to ~/.decoy/scan.json for decoy-mcp exposure analysis
function writeScanCache(results) {
  try {
    const cacheDir = join(homedir(), ".decoy");
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(join(cacheDir, "scan.json"), JSON.stringify(results, null, 2) + "\n");
  } catch {}
}

main().catch(e => {
  status(`  ${c.red}error:${c.reset} ${e.message}`);
  if (verboseMode) status(`  ${c.dim}${e.stack}${c.reset}`);
  process.exit(1);
});
