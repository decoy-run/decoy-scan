// Scan orchestration — wires discovery, probing, analysis, and reporting together.

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { EXCESSIVE_TOOL_COUNT, TOOL_DESCRIPTION_SLICE } from "./constants.mjs";
import {
  classifyTool, detectPoisoning, analyzeServerCommand, analyzeEnvExposure,
  analyzeTransport, analyzeReadiness, analyzeInputSanitization,
  analyzePermissionScope, hashToolManifest, detectManifestChanges, analyzeToxicFlows,
} from "./analyzers.mjs";
import { mapToOwasp } from "./owasp.mjs";
import { discoverConfigs } from "./discovery.mjs";
import { probeServer } from "./probe.mjs";
import { checkAdvisories, matchAdvisories } from "./advisories.mjs";
import { discoverSkills, analyzeSkill } from "./skills.mjs";

export async function scan({ probe = true, advisories = true, skills = false, customPatterns = [], configs: preloadedConfigs } = {}) {
  const configs = preloadedConfigs || discoverConfigs();
  const results = {
    timestamp: new Date().toISOString(),
    hosts: configs.map(c => c.host),
    servers: [],
    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, errors: 0, poisoned: 0, suspicious: 0, envExposures: 0, readiness: 0, transportIssues: 0, sanitizationIssues: 0, scopeIssues: 0, manifestChanges: 0, toxicFlows: 0, skillIssues: 0, findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 } },
    advisories: [],
    toxicFlows: [],
    skills: [],
    owasp: {},
  };

  // Load previous scan for manifest change detection
  let previousScan = null;
  try {
    const cachePath = join(homedir(), ".decoy", "scan.json");
    if (existsSync(cachePath)) {
      const cached = JSON.parse(readFileSync(cachePath, "utf8"));
      if (cached.version === 1) previousScan = cached;
    }
  } catch { /* No previous scan cache or corrupt JSON — skip change detection */ }

  // Deduplicate servers across hosts (by name + command + args)
  const serverMap = new Map();
  for (const { host, servers } of configs) {
    for (const [name, entry] of Object.entries(servers)) {
      const dedupKey = `${name}::${entry.command || ""}::${JSON.stringify(entry.args || [])}`;
      if (!serverMap.has(dedupKey)) {
        serverMap.set(dedupKey, { name, entry, hosts: [host] });
      } else {
        serverMap.get(dedupKey).hosts.push(host);
      }
    }
  }

  // Probe servers with concurrency limit (max 8 at a time)
  const serverOrder = [];
  for (const [, { name, entry, hosts }] of serverMap) {
    serverOrder.push({ name, entry, hosts });
  }

  async function pMap(items, fn, concurrency = 8) {
    const results = [];
    let i = 0;
    async function next() {
      const idx = i++;
      if (idx >= items.length) return;
      results[idx] = await fn(items[idx], idx);
      await next();
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => next()));
    return results;
  }

  const probeResults = await pMap(serverOrder, ({ name, entry }) => {
    if (probe) return probeServer(name, entry);
    return Promise.resolve({ name, tools: [], error: null });
  }, 8);

  for (let i = 0; i < serverOrder.length; i++) {
    const { name, entry, hosts } = serverOrder[i];
    const probeResult = probeResults[i];

    const server = {
      name,
      hosts,
      command: entry.command,
      args: entry.args || [],
      tools: [],
      risk: "low",
      error: probeResult.error || null,
      findings: [],
    };

    if (probeResult.error) {
      results.summary.errors++;
    }

    // Detect decoy tripwire server
    const isDecoy = name === "system-tools" && !!entry.env?.DECOY_TOKEN;
    if (isDecoy) server.decoy = true;

    // Classify tools
    server.tools = probeResult.tools.map(t => {
      const risk = classifyTool(t);
      const poisoning = detectPoisoning(t, { customPatterns });
      return {
        name: t.name,
        description: (t.description || "").slice(0, TOOL_DESCRIPTION_SLICE),
        risk,
        poisoning: poisoning.length > 0 ? poisoning : undefined,
      };
    });

    // Decoy servers: keep tools but skip analysis
    if (isDecoy) {
      server.risk = "info";
      results.servers.push(server);
      continue;
    }

    // Tool poisoning findings
    for (const tool of server.tools) {
      if (tool.poisoning) {
        for (const p of tool.poisoning) {
          server.findings.push({ ...p, tool: tool.name, source: "tool-description" });
          results.summary.poisoned++;
        }
      }
    }

    // Server command analysis
    for (const f of analyzeServerCommand(entry)) {
      server.findings.push({ ...f, source: f.type === "potential-typosquat" ? "typosquat" : "server-command" });
      results.summary.suspicious++;
    }

    // Env var exposure
    for (const f of analyzeEnvExposure(entry)) {
      server.findings.push({ ...f, source: "env-config" });
      results.summary.envExposures++;
    }

    // Transport security
    for (const f of analyzeTransport(entry)) {
      server.findings.push({ ...f, source: "transport" });
      results.summary.transportIssues++;
    }

    // Readiness checks per tool
    for (const tool of probeResult.tools) {
      for (const f of analyzeReadiness(tool)) {
        server.findings.push({ ...f, tool: tool.name, source: "readiness" });
        results.summary.readiness++;
      }
    }

    // Input sanitization per tool
    for (const tool of probeResult.tools) {
      for (const f of analyzeInputSanitization(tool)) {
        server.findings.push({ ...f, tool: tool.name, source: "input-sanitization" });
        results.summary.sanitizationIssues++;
      }
    }

    // Tool count warning
    if (server.tools.length > EXCESSIVE_TOOL_COUNT) {
      server.findings.push({
        type: "excessive-tools", severity: "medium",
        description: `Server exposes ${server.tools.length} tools — large attack surface`,
        source: "tool-count",
      });
    }

    // Permission scope
    for (const f of analyzePermissionScope(probeResult.tools)) {
      server.findings.push({ ...f, source: "permission-scope" });
      results.summary.scopeIssues++;
    }

    // Manifest hashing + change detection
    if (probeResult.tools.length > 0) {
      server.manifestHash = hashToolManifest(probeResult.tools);
      if (previousScan) {
        const prevServer = previousScan.servers?.find(s => s.name === name);
        if (prevServer?.tools?.length > 0) {
          server.previousManifestHash = prevServer.manifestHash;
          for (const f of detectManifestChanges(probeResult.tools, prevServer.tools)) {
            server.findings.push({ ...f, source: "manifest-change" });
            results.summary.manifestChanges++;
          }
        }
      }
    }

    // Server risk = worst across tools + findings
    const allRisks = [...server.tools.map(t => t.risk), ...server.findings.map(f => f.severity)];
    if (allRisks.includes("critical")) server.risk = "critical";
    else if (allRisks.includes("high")) server.risk = "high";
    else if (allRisks.includes("medium")) server.risk = "medium";

    // OWASP mapping
    for (const f of server.findings) {
      const owasp = mapToOwasp(f.type);
      if (owasp) {
        if (!results.owasp[owasp.id]) results.owasp[owasp.id] = { ...owasp, count: 0 };
        results.owasp[owasp.id].count++;
      }
    }
    for (const tool of server.tools) {
      if (tool.risk === "critical" || tool.risk === "high") {
        const key = `${tool.risk}-tool`;
        const owasp = mapToOwasp(key);
        if (owasp) {
          if (!results.owasp[owasp.id]) results.owasp[owasp.id] = { ...owasp, count: 0 };
          results.owasp[owasp.id].count++;
        }
      }
    }

    results.summary.total++;
    results.summary[server.risk]++;
    results.servers.push(server);

    // Count individual findings by severity (tools + config findings)
    for (const t of server.tools) {
      results.summary.findingsBySeverity[t.risk]++;
    }
    for (const f of server.findings) {
      if (f.severity && results.summary.findingsBySeverity[f.severity] !== undefined) {
        results.summary.findingsBySeverity[f.severity]++;
      }
    }
  }

  // Toxic flow analysis across all non-decoy servers
  const allNonDecoyTools = [];
  for (let i = 0; i < serverOrder.length; i++) {
    const { name, entry } = serverOrder[i];
    const isDecoy = name === "system-tools" && !!entry.env?.DECOY_TOKEN;
    if (isDecoy || probeResults[i].error) continue;
    for (const tool of probeResults[i].tools) allNonDecoyTools.push(tool);
  }
  results.toxicFlows = analyzeToxicFlows(allNonDecoyTools);
  results.summary.toxicFlows = results.toxicFlows.length;
  for (const f of results.toxicFlows) {
    const owasp = mapToOwasp(f.type);
    if (owasp) {
      if (!results.owasp[owasp.id]) results.owasp[owasp.id] = { ...owasp, count: 0 };
      results.owasp[owasp.id].count++;
    }
  }

  // Skill scanning
  if (skills) {
    const discovered = discoverSkills();
    for (const skill of discovered) {
      const skillFindings = analyzeSkill(skill);
      results.skills.push({ name: skill.name, path: skill.path, source: skill.source, type: skill.type, findings: skillFindings });
      results.summary.skillIssues += skillFindings.length;
      for (const f of skillFindings) {
        const owasp = mapToOwasp(f.type);
        if (owasp) {
          if (!results.owasp[owasp.id]) results.owasp[owasp.id] = { ...owasp, count: 0 };
          results.owasp[owasp.id].count++;
        }
      }
    }
  }

  // Check advisories
  if (advisories) {
    const advData = await checkAdvisories();
    if (advData.threats?.length > 0) {
      for (const { name, entry } of serverOrder) {
        const matches = matchAdvisories(entry, advData.threats);
        for (const m of matches) {
          results.advisories.push({ server: name, ...m });
        }
      }
    }
  }

  return results;
}
