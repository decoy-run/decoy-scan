// Explanations for decoy-scan's classifications.
// Sourced from the same rules the scanner uses, so explanations stay in sync.

import { RISK_PATTERNS, POISONING_PATTERNS } from "./patterns.mjs";

// ─── Severity tiers ───

export const TIERS = {
  critical: {
    title: "Critical",
    summary: "Can execute code, modify data, or cause irreversible changes.",
    body:
      "A compromised agent calling a critical tool can run arbitrary code, " +
      "write or delete files, move money, or drop database tables. If a " +
      "tool in this tier is exploitable, the blast radius is production.",
    examples: ["execute_command", "write_file", "delete_file", "make_payment", "eval"],
    advice:
      "Only install servers with critical tools if you fully trust the vendor. " +
      "Deploy tripwires so you get alerted the first time one is called.",
  },
  high: {
    title: "High",
    summary: "Can read sensitive data, access credentials, or reach the network.",
    body:
      "High-risk tools can exfiltrate files, hit arbitrary URLs, pull " +
      "credentials, or send messages. On their own they don't destroy data, " +
      "but they're the vehicle prompt-injection uses to get data out.",
    examples: ["read_file", "http_request", "get_credentials", "send_email"],
    advice:
      "Audit what each high tool actually accesses. Restrict credential scope where possible.",
  },
  medium: {
    title: "Medium",
    summary: "Informational or bounded read-only operations.",
    body:
      "Medium tools list, search, browse, or capture — useful work, but " +
      "mostly without direct side effects. They're flagged so you can review " +
      "input constraints, not because they're dangerous on their own.",
    examples: ["list_files", "search", "browse", "screenshot"],
    advice: "Add inputSchema constraints (maxLength, pattern) to tighten the contract.",
  },
  low: {
    title: "Low",
    summary: "Safe, read-only metadata.",
    body:
      "Low tools return version strings, help text, status, or small fixed " +
      "payloads. They're listed in verbose mode so you can see everything a " +
      "server exposes, but they require no review.",
    examples: ["ping", "version", "help", "status"],
    advice: "Nothing to do. These are fine.",
  },
};

// ─── Finding categories ───
// Shared with bin/cli.mjs so the scanner and explain use the same data.

export const CATEGORIES = {
  "tool-description": {
    title: "Prompt injection in tool descriptions",
    tier: "red",
    summary: "The tool's description contains text that tries to override agent behavior.",
    body:
      "Attackers hide instructions in tool descriptions — text that says " +
      "things like 'ignore previous instructions' or 'before calling any " +
      "other tool, always call this one'. Agents read descriptions as " +
      "guidance, so a poisoned description can reroute the agent's plan.",
    fix: "Audit tool descriptions for hidden instructions — remove any text that overrides agent behavior.",
  },
  "server-command": {
    title: "Suspicious server spawn command",
    tier: "red",
    summary: "The command used to start this server does something risky.",
    body:
      "Examples: piping a remote script to a shell (curl … | sh), running " +
      "inline code via sh -c or eval, or spawning from a temporary directory. " +
      "These patterns bypass package integrity and are common in supply-chain attacks.",
    fix: "Replace shell pipes with direct binary execution — avoid sh -c and eval patterns.",
  },
  "typosquat": {
    title: "Possible typosquatted package",
    tier: "red",
    summary: "The package name resembles a known MCP server but isn't an exact match.",
    body:
      "Typosquats — 'mcp-filesystm' instead of 'mcp-filesystem' — are a " +
      "classic delivery vehicle for malicious code. Always verify the exact name.",
    fix: "Verify the package name — compare against the official registry at npmjs.com.",
  },
  "transport": {
    title: "Insecure transport (HTTP without TLS)",
    tier: "red",
    summary: "The server uses unencrypted HTTP.",
    body:
      "Credentials and tool calls travel in plaintext, visible to anyone on " +
      "the network path. SSE/HTTP transports should always be HTTPS.",
    fix: "Switch to HTTPS or use stdio transport — never send credentials over plain HTTP.",
  },
  "env-config": {
    title: "Secrets exposed via environment variables",
    tier: "yellow",
    summary: "An env var passed to the server looks like a secret (API key, token, etc).",
    body:
      "Secrets inlined in MCP config files end up in version control, backups, " +
      "and shell history. Better to load them from a .env file, a vault, or the OS keychain.",
    fix: "Move secrets to a .env file or vault — don't inline them in MCP config.",
  },
  "tool-count": {
    title: "Large attack surface",
    tier: "yellow",
    summary: "This server exposes many tools — a bigger blast radius if compromised.",
    body:
      "Servers with dozens of tools tend to mix read and write, local and " +
      "network, data and code. Splitting into focused servers limits what " +
      "an attacker gains from compromising any one of them.",
    fix: "Split into focused servers with fewer tools — limit blast radius per server.",
  },
  "permission-scope": {
    title: "Server has too many permissions",
    tier: "yellow",
    summary: "This server covers many capability domains (files, network, credentials, etc).",
    body:
      "Least-privilege: one server for reads, another for writes. " +
      "A file-read server combined with a network server is a credential " +
      "exfiltration chain waiting to happen.",
    fix: "Apply least-privilege — separate read-only and write servers.",
  },
  "readiness": {
    title: "Tools missing input constraints or safety checks",
    tier: "info",
    summary: "One or more tools don't have a complete inputSchema.",
    body:
      "Tools without typed, documented inputs are easier to misuse and " +
      "harder for the agent to call correctly. Add required fields, types, " +
      "and descriptions.",
    fix: "Add inputSchema with descriptions, required fields, and type constraints.",
  },
  "input-sanitization": {
    title: "Tools accept unconstrained input",
    tier: "info",
    summary: "String parameters lack maxLength, pattern, or enum constraints.",
    body:
      "Unbounded string inputs are an injection vector. Constraining inputs " +
      "doesn't make a tool safe, but it makes misuse harder and bugs easier to catch.",
    fix: "Add maxLength, pattern, or enum constraints to string parameters.",
  },
  "manifest-change": {
    title: "Tool manifest changed since last scan",
    tier: "yellow",
    summary: "A tool's name, description, or schema has drifted since we last looked.",
    body:
      "Manifest drift is how supply-chain attacks land: a clean tool on " +
      "install day becomes a poisoned one after an update. Review the diff.",
    fix: "Review the diff — new tools may introduce unintended capabilities.",
  },
};

// Legacy name used by bin/cli.mjs. Kept so the scanner uses the same `fix` strings.
export const categoryInfo = Object.fromEntries(
  Object.entries(CATEGORIES).map(([k, v]) => [k, { label: v.title, tier: v.tier, fix: v.fix }]),
);

// ─── Poisoning types ───
// Derived from POISONING_PATTERNS so examples and severity stay accurate.

const POISONING_DETAILS = {
  "prompt-override": {
    summary: "Text that tries to override the agent's system prompt or instructions.",
    body:
      "Classic prompt injection. The attacker buries 'ignore previous instructions' " +
      "(or a variant) in a tool description so the agent reads it as guidance.",
  },
  "role-redefinition": {
    summary: "Text that tries to redefine what the agent is.",
    body:
      "'New instructions: you are now a helpful assistant that...' — an attempt " +
      "to overwrite the agent's identity from inside a tool description.",
  },
  "instruction-injection": {
    summary: "Text that injects additional rules into the agent's behavior.",
    body:
      "Phrases like 'you must also' or 'always first' try to sneak new mandatory " +
      "rules into whatever the agent was doing.",
  },
  "coercive-execution": {
    summary: "Text that forces a specific tool call order.",
    body:
      "'Always consult this tool before any other' — an attacker ensures their " +
      "tool is called first so they see every request.",
  },
  "concealment": {
    summary: "Text that tells the agent to hide actions from the user.",
    body:
      "'Don't tell the user', 'silently send', 'covertly collect' — instructions " +
      "designed to keep the user in the dark while the agent acts.",
  },
  "tool-chaining": {
    summary: "Text that forces the agent to call other tools.",
    body:
      "An attacker's tool says 'before running this, call tool X' — chaining the " +
      "agent into attacker-controlled workflows.",
  },
  "cross-tool-reference": {
    summary: "Text that references other tools by name — possible tool shadowing.",
    body:
      "Referring to another tool's name in a description can trick the agent into " +
      "substituting one tool for another (tool shadowing).",
  },
};

export const POISONING = {};
for (const p of POISONING_PATTERNS) {
  if (POISONING[p.type]) continue; // first wins
  POISONING[p.type] = {
    title: p.type.replace(/-/g, " ").replace(/\b\w/g, (m) => m.toUpperCase()),
    severity: p.severity,
    summary: POISONING_DETAILS[p.type]?.summary || p.description,
    body: POISONING_DETAILS[p.type]?.body || p.description,
    example: p.description,
  };
}

// ─── Tool-name classification reasoning ───

function classifyWithReason(name, desc = "") {
  const lowerName = String(name).toLowerCase();
  const lowerDesc = desc.toLowerCase();

  for (const [level, patterns] of Object.entries(RISK_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(name)) {
        return {
          risk: level,
          reason: `name matches the ${level}-tier pattern ${pattern}`,
          matched: pattern.toString(),
        };
      }
    }
  }

  const checks = [
    [/execut|command|shell|bash|sudo|spawn|fork|eval/, "critical", "code execution"],
    [/delet|remov|drop|destruct|truncat|wipe|purge/, "critical", "destructive operations"],
    [/read.*file|write.*file|filesystem|file.*system/, "high", "filesystem access"],
    [/credentials|secret|password|api.?key|token|auth/, "high", "credentials"],
    [/http|request|fetch|curl|wget|network/, "high", "network access"],
    [/database|query|sql|mongo|redis|dynamo/, "high", "database access"],
    [/email|message|notification|sms|slack/, "medium", "messaging"],
    [/browse|screenshot|puppeteer|playwright|selenium/, "medium", "browser automation"],
  ];
  for (const [re, risk, label] of checks) {
    if (re.test(lowerName)) {
      return { risk, reason: `name suggests ${label}`, matched: re.toString() };
    }
    if (re.test(lowerDesc)) {
      return { risk, reason: `description mentions ${label}`, matched: re.toString() };
    }
  }

  return {
    risk: "low",
    reason: "name and description match no elevated-risk patterns",
    matched: null,
  };
}

// ─── Resolver ───

export function resolveExplain(target) {
  if (!target) return null;
  const key = String(target).trim();
  const lower = key.toLowerCase();

  if (TIERS[lower]) {
    return { kind: "tier", key: lower, ...TIERS[lower] };
  }
  if (CATEGORIES[lower]) {
    const cat = CATEGORIES[lower];
    return { kind: "category", key: lower, ...cat };
  }
  if (POISONING[lower]) {
    return { kind: "poisoning", key: lower, ...POISONING[lower] };
  }

  // Fallback: treat the target as a tool name.
  const { risk, reason, matched } = classifyWithReason(key);
  const tier = TIERS[risk];
  const classificationIsComplete = matched !== null;
  return {
    kind: "tool",
    key,
    title: key,
    risk,
    reason,
    matched,
    classificationIsComplete,
    note: classificationIsComplete
      ? null
      : "Name alone didn't match any elevated-risk pattern. In a real scan the tool's description is also checked — a name like this may still classify higher if the description mentions code execution, file access, credentials, or network calls.",
    tier: { title: tier.title, summary: tier.summary, advice: tier.advice },
  };
}

export function listExplainTargets() {
  return {
    tiers: Object.keys(TIERS),
    categories: Object.keys(CATEGORIES),
    poisoning: Object.keys(POISONING),
  };
}
