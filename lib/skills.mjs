// Skill scanning — discovers and analyzes Claude Code skills for injection and secrets.

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { POISONING_PATTERNS, SKILL_SECRET_PATTERNS, TRUSTED_HOSTS } from "./patterns.mjs";
import { SKILL_NAME_MAX } from "./constants.mjs";

// ─── Frontmatter parsing ───

function parseSkillFrontmatter(content) {
  const frontmatter = {};
  let body = content;

  const match = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/);
  if (match) {
    body = match[2];
    for (const line of match[1].split("\n")) {
      const kv = line.match(/^(\S[^:]*?):\s*(.*)$/);
      if (kv) {
        let [, key, value] = kv;
        value = value.trim();
        if (value.startsWith("[") && value.endsWith("]")) {
          try { value = JSON.parse(value); } catch { /* Not valid JSON array — keep as raw string */ }
        } else if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        frontmatter[key] = value;
      }
    }
  }
  return { frontmatter, body };
}

// ─── Recursive skill file discovery ───

function findSkillFiles(dirPath, source, skills) {
  try {
    const entries = readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name);
      if (entry.isDirectory()) {
        findSkillFiles(fullPath, source, skills);
      } else if (entry.name.endsWith(".md") && !["README.md", "LICENSE.md", "CHANGELOG.md", "CONTRIBUTING.md", "AGENTS.md"].includes(entry.name)) {
        let type = "unknown";
        if (entry.name === "SKILL.md") type = "skill";
        else if (fullPath.includes("/commands/")) type = "command";
        else if (fullPath.includes("/agents/")) type = "agent";
        else continue;

        try {
          const content = readFileSync(fullPath, "utf8");
          const parsed = parseSkillFrontmatter(content);
          skills.push({
            name: parsed.frontmatter.name || parsed.frontmatter.description?.slice(0, SKILL_NAME_MAX) || entry.name.replace(".md", ""),
            path: fullPath,
            source,
            type,
            content,
            frontmatter: parsed.frontmatter,
            body: parsed.body,
          });
        } catch { /* Unreadable skill file — skip */ }
      }
    }
  } catch { /* Directory not readable or disappeared mid-walk — skip */ }
}

// ─── Discovery ───

export function discoverSkills() {
  const skills = [];
  const home = homedir();

  const officialCache = join(home, ".claude", "plugins", "cache", "claude-plugins-official");
  const marketplace = join(home, ".claude", "plugins", "marketplaces", "claude-code-plugins", "plugins");
  const projectCommands = join(process.cwd(), ".claude", "commands");

  if (existsSync(officialCache)) findSkillFiles(officialCache, "official", skills);
  if (existsSync(marketplace)) findSkillFiles(marketplace, "marketplace", skills);
  if (existsSync(projectCommands)) findSkillFiles(projectCommands, "project", skills);

  return skills;
}

// ─── Analysis ───

export function analyzeSkill(skill) {
  const findings = [];
  const body = skill.body || "";
  const fm = skill.frontmatter || {};

  // Prompt injection (reuse poisoning patterns on skill body)
  for (const { pattern, type, severity, description } of POISONING_PATTERNS) {
    if (pattern.test(body)) {
      findings.push({ type: "skill-" + type, severity, description: `Skill: ${description}` });
    }
  }

  // Hardcoded secrets
  for (const { pattern, type, description } of SKILL_SECRET_PATTERNS) {
    if (pattern.test(skill.content)) {
      findings.push({ type, severity: "critical", description });
    }
  }

  // Suspicious URLs
  const urls = skill.content.match(/https?:\/\/[^\s)"'>]+/gi) || [];
  for (const url of urls) {
    try {
      const host = new URL(url).hostname;
      if (!TRUSTED_HOSTS.test(host)) {
        findings.push({ type: "skill-suspicious-url", severity: "medium", description: `References external URL: ${url.slice(0, 100)}` });
        break;
      }
    } catch { /* Malformed URL — not a valid link, skip */ }
  }

  // Overly broad tool access
  const allowedTools = fm["allowed-tools"] || fm.tools;
  if (allowedTools) {
    const toolList = Array.isArray(allowedTools) ? allowedTools : String(allowedTools).split(",").map(t => t.trim());
    if (toolList.includes("*")) {
      findings.push({ type: "skill-wildcard-tools", severity: "high", description: "Skill has wildcard tool access" });
    }
    if (toolList.some(t => t === "Bash" || /^Bash\(\*\)$/.test(t))) {
      findings.push({ type: "skill-unrestricted-bash", severity: "high", description: "Skill has unrestricted Bash access" });
    }
  }

  // Instructions to expose credentials
  if (/\b(include|output|print|display|show|return)\b.*\b(api.?key|token|secret|password|credential)/i.test(body)) {
    findings.push({ type: "skill-credential-output", severity: "high", description: "Skill instructs including credentials in output" });
  }

  return findings;
}
