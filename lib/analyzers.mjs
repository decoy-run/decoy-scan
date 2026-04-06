// Analysis functions — pure, composable, no side effects.
// Each takes a tool/entry/array, returns structured findings.

import { createHash } from "node:crypto";
import {
  RISK_PATTERNS, POISONING_PATTERNS, SENSITIVE_ENV_PATTERNS,
  TOOL_ROLE_PATTERNS, CAPABILITY_PATTERNS, KNOWN_MCP_PACKAGES,
} from "./patterns.mjs";
import {
  EXCESSIVE_DESCRIPTION_LENGTH, MIN_DESCRIPTION_LENGTH,
  OVERLOADED_SCOPE_THRESHOLD, GOD_MODE_DOMAIN_THRESHOLD,
  MANIFEST_HASH_LENGTH, BASE64_MIN_LENGTH, POISONING_MATCH_SLICE,
} from "./constants.mjs";

// ─── Risk Classification ───

export function classifyTool(tool) {
  const name = tool.name || "";
  const desc = (tool.description || "").toLowerCase();

  for (const [level, patterns] of Object.entries(RISK_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(name)) return level;
    }
  }

  // Description-based fallback
  if (/execut|command|shell|bash|sudo|spawn|fork|eval/.test(desc)) return "critical";
  if (/delet|remov|drop|destruct|truncat|wipe|purge/.test(desc)) return "critical";
  if (/read.*file|write.*file|filesystem|file.*system/.test(desc)) return "high";
  if (/credentials|secret|password|api.?key|token|auth/.test(desc)) return "high";
  if (/http|request|fetch|curl|wget|network/.test(desc)) return "high";
  if (/database|query|sql|mongo|redis|dynamo/.test(desc)) return "high";
  if (/email|message|notification|sms|slack/.test(desc)) return "medium";
  if (/browse|screenshot|puppeteer|playwright|selenium/.test(desc)) return "medium";

  return "low";
}

// ─── Tool Poisoning Detection ───

export function detectPoisoning(tool, { customPatterns = [] } = {}) {
  const text = `${tool.name || ""} ${tool.description || ""}`;
  const findings = [];
  const allPatterns = [...POISONING_PATTERNS, ...customPatterns];

  for (const { pattern, type, severity, description } of allPatterns) {
    if (pattern.test(text)) {
      findings.push({ type, severity, description, match: text.match(pattern)?.[0]?.slice(0, POISONING_MATCH_SLICE) });
    }
  }

  if ((tool.description || "").length > EXCESSIVE_DESCRIPTION_LENGTH) {
    findings.push({ type: "excessive-length", severity: "medium", description: `Tool description is ${tool.description.length} chars (suspiciously long)` });
  }

  return findings;
}

// ─── Server Command Analysis ───

export function analyzeServerCommand(entry) {
  const cmd = entry.command || "";
  const args = (entry.args || []).join(" ");
  const full = `${cmd} ${args}`;
  const findings = [];

  // Running from temp/untrusted directories (npx uses temp dirs — that's normal)
  const isNpx = /\bnpx\b/.test(cmd);
  if (!isNpx && /\/(tmp|temp|var\/tmp|dev\/shm)\//i.test(full)) {
    findings.push({ type: "temp-directory", severity: "high", description: "Server runs from temporary directory" });
  }

  // Pipe to shell
  if (/curl.*\|\s*(sh|bash|zsh)|wget.*\|\s*(sh|bash|zsh)/i.test(full)) {
    findings.push({ type: "pipe-to-shell", severity: "critical", description: "Server command pipes remote content to shell" });
  }

  // Suspicious binaries
  if (/\b(nc|netcat|ncat|socat|telnet)\b/i.test(cmd)) {
    findings.push({ type: "network-tool", severity: "high", description: `Server uses network tool: ${cmd}` });
  }

  // Base64 encoded arguments
  const base64Re = new RegExp(`[A-Za-z0-9+/]{${BASE64_MIN_LENGTH},}={0,2}`);
  if (base64Re.test(args)) {
    findings.push({ type: "encoded-args", severity: "medium", description: "Arguments may contain base64-encoded content" });
  }

  // Python/Node one-liners
  if (/python[23]?\s+-c\s+/i.test(full) || /node\s+-e\s+/i.test(full)) {
    findings.push({ type: "inline-code", severity: "high", description: "Server runs inline code rather than a file" });
  }

  // Typosquatting in npx commands
  if (/npx\s+/.test(full)) {
    const pkg = full.match(/npx\s+(?:-[a-z]+\s+)*([a-z0-9@][a-z0-9@._/-]*)/i)?.[1];
    if (pkg && !KNOWN_MCP_PACKAGES.has(pkg) && /^@?m[ce]p-?server/i.test(pkg)) {
      findings.push({ type: "potential-typosquat", severity: "high", description: `Package "${pkg}" resembles MCP server naming but isn't in known list` });
    }
  }

  return findings;
}

// ─── Environment Variable Exposure ───

export function analyzeEnvExposure(entry) {
  const env = entry.env || {};
  const findings = [];

  for (const [key] of Object.entries(env)) {
    for (const { pattern, type } of SENSITIVE_ENV_PATTERNS) {
      if (pattern.test(key)) {
        findings.push({
          type: "env-exposure",
          severity: "high",
          description: `Passes ${type} to server via env var "${key}"`,
          envVar: key,
        });
        break;
      }
    }
  }

  return findings;
}

// ─── SSE Transport Security ───

export function analyzeTransport(entry) {
  const findings = [];
  const cmd = entry.command || "";
  const args = (entry.args || []).join(" ");
  const full = `${cmd} ${args}`;
  const env = entry.env || {};
  const url = entry.url || "";

  const isSSE = !!(entry.url || /\b(sse|server-sent|streamable-http)\b/i.test(full) ||
    /--transport\s+(sse|http)/i.test(full) ||
    entry.transport === "sse" || entry.transport === "streamable-http");

  if (!isSSE && !url) return findings;

  // SSE-001: HTTP instead of HTTPS
  const targetUrl = url || full.match(/https?:\/\/[^\s"']+/)?.[0] || "";
  if (targetUrl && /^http:\/\//i.test(targetUrl) && !/localhost|127\.0\.0\.1|::1|\[::1\]/.test(targetUrl)) {
    findings.push({ type: "sse-no-tls", severity: "critical", description: "SSE transport uses unencrypted HTTP — credentials and tool calls transmitted in plaintext" });
  }

  // SSE-002: No authentication
  const hasAuth = env.API_KEY || env.AUTH_TOKEN || env.BEARER_TOKEN || env.ACCESS_TOKEN ||
    /--auth|--token|--api-key|--bearer|authorization/i.test(full) ||
    Object.keys(env).some(k => /auth|bearer|api.?key/i.test(k));
  if (isSSE && !hasAuth) {
    findings.push({ type: "sse-no-auth", severity: "high", description: "SSE server has no visible authentication configured — any client can connect" });
  }

  // SSE-003: Wildcard CORS
  if (/--cors\s+\*|cors.*origin.*\*|CORS_ORIGIN.*\*/i.test(full) || env.CORS_ORIGIN === "*") {
    findings.push({ type: "sse-cors-wildcard", severity: "high", description: "SSE server allows wildcard CORS origin — vulnerable to cross-origin attacks" });
  }

  // SSE-004: Exposed on 0.0.0.0
  if (/\b0\.0\.0\.0\b|--host\s+0\.0\.0\.0|BIND_ADDRESS.*0\.0\.0\.0/i.test(full) ||
      env.HOST === "0.0.0.0" || env.BIND_ADDRESS === "0.0.0.0") {
    findings.push({ type: "sse-public-bind", severity: "high", description: "SSE server binds to all interfaces (0.0.0.0) — accessible from network" });
  }

  // SSE-005: No rate limiting
  if (isSSE && !/rate.?limit|max.?connections|throttl/i.test(full) &&
      !Object.keys(env).some(k => /rate|limit|throttl|max.?conn/i.test(k))) {
    findings.push({ type: "sse-no-rate-limit", severity: "medium", description: "SSE server has no visible rate limiting — vulnerable to connection exhaustion" });
  }

  return findings;
}

// ─── Readiness Analysis ───

export function analyzeReadiness(tool) {
  const findings = [];
  const desc = (tool.description || "").toLowerCase();
  const schema = tool.inputSchema || {};

  if (!tool.description || tool.description.length < MIN_DESCRIPTION_LENGTH) {
    findings.push({ type: "readiness-no-description", severity: "medium", description: "Tool has no or very short description — agents will misuse it" });
  }

  if (!tool.inputSchema || Object.keys(tool.inputSchema).length === 0) {
    findings.push({ type: "readiness-no-schema", severity: "medium", description: "Tool has no input schema — accepts arbitrary input" });
  }

  if (schema.type === "object" && (!schema.required || schema.required.length === 0)) {
    const propCount = Object.keys(schema.properties || {}).length;
    if (propCount > 0) {
      findings.push({ type: "readiness-no-required", severity: "low", description: `Tool has ${propCount} parameters but none are required` });
    }
  }

  const scopeWords = (desc.match(/\b(and|also|plus|additionally|furthermore|as well as)\b/gi) || []).length;
  if (scopeWords >= OVERLOADED_SCOPE_THRESHOLD) {
    findings.push({ type: "readiness-overloaded", severity: "low", description: `Tool description suggests overloaded scope (${scopeWords} conjunctions)` });
  }

  if (/\b(delet\w*|remov\w*|drop\w*|truncat\w*|destroy\w*|wipe|purge|overwrite|reset)\b/i.test(desc)) {
    if (!/\b(confirm|safe|undo|backup|revert|dry.?run|preview)\b/i.test(desc)) {
      findings.push({ type: "readiness-dangerous-no-safety", severity: "medium", description: "Destructive tool lacks safety hints (confirm, undo, dry-run)" });
    }
  }

  return findings;
}

// ─── Input Sanitization ───

export function analyzeInputSanitization(tool) {
  const findings = [];
  const schema = tool.inputSchema || {};
  const props = schema.properties || {};
  const risk = classifyTool(tool);

  if (risk === "low") return findings;

  for (const [propName, propSchema] of Object.entries(props)) {
    if (!propSchema.type && !propSchema.enum && !propSchema.oneOf && !propSchema.anyOf) {
      findings.push({ type: "sanitization-no-type", severity: "medium", description: `Parameter "${propName}" has no type constraint — accepts any value` });
    }
  }

  const dangerousParams = /command|query|sql|script|code|exec|shell|url|path|file/i;
  for (const [propName, propSchema] of Object.entries(props)) {
    if (propSchema.type === "string" && dangerousParams.test(propName)) {
      const hasConstraint = propSchema.pattern || propSchema.enum || propSchema.maxLength ||
        propSchema.format || propSchema.const;
      if (!hasConstraint) {
        findings.push({ type: "sanitization-unconstrained-dangerous", severity: risk === "critical" ? "high" : "medium", description: `Dangerous parameter "${propName}" accepts unconstrained string input` });
      }
    }
  }

  if (risk === "critical" || risk === "high") {
    const stringParams = Object.entries(props).filter(([, s]) => s.type === "string" && !s.maxLength && !s.enum);
    if (stringParams.length > 0) {
      findings.push({ type: "sanitization-no-maxlength", severity: "low", description: `${stringParams.length} string parameter${stringParams.length > 1 ? "s" : ""} without maxLength on ${risk}-risk tool` });
    }
  }

  for (const [propName, propSchema] of Object.entries(props)) {
    if (propSchema.type === "object" && !propSchema.properties && !propSchema.additionalProperties) {
      findings.push({ type: "sanitization-open-object", severity: "medium", description: `Parameter "${propName}" accepts arbitrary object without property constraints` });
    }
    if (propSchema.type === "array" && !propSchema.items && !propSchema.maxItems) {
      findings.push({ type: "sanitization-open-array", severity: "medium", description: `Parameter "${propName}" accepts unbounded array without item constraints` });
    }
  }

  if (risk === "critical" && schema.type === "object" && schema.additionalProperties !== false && Object.keys(props).length > 0) {
    findings.push({ type: "sanitization-additional-props", severity: "low", description: "Critical tool schema allows additional properties beyond defined parameters" });
  }

  return findings;
}

// ─── Permission Scope ───

export function analyzePermissionScope(tools) {
  const findings = [];
  const capabilities = {
    filesystem: { read: false, write: false },
    network: { inbound: false, outbound: false },
    execution: { shell: false, code: false },
    data: { database: false, credentials: false },
    communication: { email: false, messaging: false },
    infrastructure: { dns: false, deploy: false, billing: false },
  };

  for (const tool of tools) {
    const name = tool.name || "";
    for (const [capPath, pattern] of Object.entries(CAPABILITY_PATTERNS)) {
      if (pattern.test(name)) {
        const [category, sub] = capPath.split(".");
        capabilities[category][sub] = true;
      }
    }
  }

  const activeDomains = Object.entries(capabilities).filter(([, subs]) =>
    Object.values(subs).some(v => v)
  ).map(([name]) => name);

  if (activeDomains.length >= GOD_MODE_DOMAIN_THRESHOLD) {
    findings.push({ type: "scope-overprivileged", severity: "high", description: `Server has ${activeDomains.length}/6 capability domains (${activeDomains.join(", ")}) — likely over-scoped` });
  }

  if (capabilities.execution.shell && capabilities.network.outbound) {
    findings.push({ type: "scope-dangerous-combo", severity: "critical", description: "Server combines shell execution with network access — enables remote code execution chains" });
  }
  if (capabilities.data.credentials && capabilities.network.outbound) {
    findings.push({ type: "scope-dangerous-combo", severity: "critical", description: "Server combines credential access with network access — enables credential exfiltration" });
  }
  if (capabilities.filesystem.write && capabilities.execution.shell) {
    findings.push({ type: "scope-dangerous-combo", severity: "high", description: "Server combines file write with shell execution — enables persistent code execution" });
  }

  return findings;
}

// ─── Tool Manifest Hashing ───

export function hashToolManifest(tools) {
  const canonical = tools
    .map(t => ({ name: t.name, description: t.description, schema: t.inputSchema }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex").slice(0, MANIFEST_HASH_LENGTH);
}

export function detectManifestChanges(currentTools, previousTools) {
  const findings = [];
  const prevMap = new Map((previousTools || []).map(t => [t.name, t]));
  const currMap = new Map((currentTools || []).map(t => [t.name, t]));

  for (const [name] of currMap) {
    if (!prevMap.has(name)) {
      findings.push({ type: "manifest-new-tool", severity: "medium", description: `New tool "${name}" added since last scan` });
    }
  }
  for (const [name] of prevMap) {
    if (!currMap.has(name)) {
      findings.push({ type: "manifest-removed-tool", severity: "high", description: `Tool "${name}" removed since last scan` });
    }
  }
  for (const [name, curr] of currMap) {
    const prev = prevMap.get(name);
    if (prev && curr.description !== prev.description) {
      findings.push({ type: "manifest-description-changed", severity: "high", description: `Tool "${name}" description changed since last scan` });
    }
  }
  return findings;
}

// ─── Toxic Flow Detection ───

function classifyToolRoles(tool) {
  const roles = new Set();
  const name = tool.name || "";
  const desc = tool.description || "";

  for (const [role, patterns] of Object.entries(TOOL_ROLE_PATTERNS)) {
    for (const p of patterns.names) {
      if (p.test(name)) { roles.add(role); break; }
    }
    if (patterns.desc.test(desc)) roles.add(role);
  }
  return [...roles];
}

export function analyzeToxicFlows(allTools) {
  const findings = [];
  const roleMap = { untrusted_content: [], private_data: [], public_sink: [], destructive: [] };

  for (const tool of allTools) {
    for (const role of classifyToolRoles(tool)) {
      if (!roleMap[role].includes(tool.name)) roleMap[role].push(tool.name);
    }
  }

  if (roleMap.untrusted_content.length > 0 && roleMap.private_data.length > 0 && roleMap.public_sink.length > 0) {
    findings.push({
      type: "toxic-flow-data-leak", severity: "critical", id: "TF001",
      description: "Data leak: untrusted content can reach private data and exfiltrate via public sink",
      roles: { untrusted_content: roleMap.untrusted_content, private_data: roleMap.private_data, public_sink: roleMap.public_sink },
    });
  }

  if (roleMap.untrusted_content.length > 0 && roleMap.destructive.length > 0) {
    findings.push({
      type: "toxic-flow-destructive", severity: "critical", id: "TF002",
      description: "Destructive flow: untrusted content can trigger irreversible operations",
      roles: { untrusted_content: roleMap.untrusted_content, destructive: roleMap.destructive },
    });
  }

  return findings;
}
