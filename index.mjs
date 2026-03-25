// decoy-scan — MCP supply chain scanner
// Scans your MCP server configurations for risky tools, vulnerable packages, and suspicious servers.

import { spawn } from "node:child_process";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { homedir, platform } from "node:os";
import { createHash } from "node:crypto";

// ─── Risk Classification ───

const RISK_PATTERNS = {
  critical: [
    /^execute[_-]?command$/i, /^run[_-]?command$/i, /^shell$/i, /^bash$/i, /^exec$/i,
    /^write[_-]?file$/i, /^create[_-]?file$/i, /^overwrite[_-]?file$/i,
    /^make[_-]?payment$/i, /^send[_-]?payment$/i, /^transfer[_-]?funds$/i,
    /^authorize[_-]?service$/i, /^grant[_-]?access$/i, /^elevate[_-]?privilege$/i,
    /^modify[_-]?dns$/i, /^update[_-]?dns$/i,
    /^delete[_-]?file$/i, /^remove[_-]?file$/i, /^unlink$/i,
    /^drop[_-]?table$/i, /^delete[_-]?database$/i, /^truncate$/i,
    /^eval$/i, /^spawn$/i, /^fork$/i,
  ],
  high: [
    /^read[_-]?file$/i, /^get[_-]?file$/i, /^cat$/i,
    /^http[_-]?request$/i, /^fetch$/i, /^curl$/i, /^wget$/i,
    /^database[_-]?query$/i, /^sql[_-]?query$/i, /^run[_-]?query$/i, /^query$/i,
    /^access[_-]?credentials$/i, /^get[_-]?credentials$/i, /^get[_-]?secrets$/i, /^get[_-]?password$/i,
    /^send[_-]?email$/i, /^send[_-]?message$/i, /^send[_-]?notification$/i,
    /^install[_-]?package$/i, /^npm[_-]?install$/i, /^pip[_-]?install$/i, /^apt[_-]?install$/i,
    /^get[_-]?environment$/i, /^env[_-]?vars$/i, /^get[_-]?env$/i,
    /^modify[_-]?config$/i, /^set[_-]?config$/i,
  ],
  medium: [
    /^list[_-]?dir/i, /^list[_-]?files/i, /^readdir$/i,
    /^search/i, /^find/i, /^glob/i, /^grep/i,
    /^upload/i, /^download/i,
    /^git[_-]/i,
    /^browse/i, /^navigate/i, /^screenshot/i,
  ],
};

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
// Detects hidden prompt injection in tool descriptions — OWASP ASI02

const POISONING_PATTERNS = [
  // Instruction override
  { pattern: /\bignore\b.*\b(previous|above|prior)\b.*\b(instructions?|prompt|rules?)\b/i, type: "prompt-override", severity: "critical", description: "Attempts to override agent instructions" },
  { pattern: /\b(bypass|disregard|forget)\s+((all|any)\s+)?(safety\s+)?guidelines/i, type: "prompt-override", severity: "critical", description: "Attempts to bypass safety guidelines" },
  { pattern: /\bsystem\s*prompt\s*override\b/i, type: "prompt-override", severity: "critical", description: "Attempts system prompt override" },
  { pattern: /\bnew\s+(instructions|directives?|guidelines)\s*:\s*you\s+are\b/i, type: "role-redefinition", severity: "critical", description: "Attempts to redefine agent role" },

  // Instruction injection
  { pattern: /\byou\s+(must|should|need\s+to|have\s+to)\s+(also|first|always)\b/i, type: "instruction-injection", severity: "critical", description: "Injects additional instructions into agent behavior" },
  { pattern: /\balways\s+(consult|use|run|execute|invoke|call)\s+this\s+tool\s+(first|before|immediately)/i, type: "coercive-execution", severity: "critical", description: "Forces mandatory tool execution order" },
  { pattern: /\b(before|prior\s+to)\s+(executing|invoking|running|using)\s+any\s+other\s+tool/i, type: "coercive-execution", severity: "critical", description: "Coerces execution priority over other tools" },
  { pattern: /\btool\s+will\s+not\s+work\s+(unless|without)/i, type: "coercive-execution", severity: "high", description: "Threatens tool failure to coerce behavior" },

  // Concealment
  { pattern: /\b(do\s+not|don'?t|never)\s+(tell|inform|reveal|show|mention)\b/i, type: "concealment", severity: "critical", description: "Attempts to hide actions from the user" },
  { pattern: /\b(invisibly|silently|covertly|secretly|without\s+(user\s+)?knowledge)\s+(send|upload|transmit|collect)/i, type: "concealment", severity: "critical", description: "Hidden data transfer without user knowledge" },
  { pattern: /\btell\s+(the\s+)?user\s+only\s+about\b/i, type: "concealment", severity: "high", description: "Selectively hides information from user" },

  // Tool chaining / shadowing
  { pattern: /\b(before|after)\s+(calling|using|executing)\s+this\s+tool.*\b(call|use|execute|invoke)\b/i, type: "tool-chaining", severity: "high", description: "Forces agent to call other tools" },
  // Cross-tool reference: only flag when it looks like injection (quoted tool names, imperative instructions to call other tools).
  // "Use this tool when..." is normal. "Call the 'admin_tool' tool first" is suspicious.
  { pattern: /\b(call|invoke|execute)\s+(the\s+)?['"`]\w+['"`]\s+(tool|function|command)\b/i, type: "cross-tool-reference", severity: "high", description: "References other tools by name (potential shadowing)" },
  { pattern: /\b(must|should|need\s+to)\s+(also\s+)?(call|invoke|use|execute)\s+(the\s+)?\w+\s+tool\b/i, type: "cross-tool-reference", severity: "high", description: "Instructs agent to call another tool" },
  { pattern: /\bshadow\b.*\btrusted\b.*\btool\b/i, type: "tool-shadowing", severity: "critical", description: "Explicitly references tool shadowing technique" },

  // Data exfiltration in descriptions
  { pattern: /\b(upload|send|transmit|forward|sync)\s+(to|data\s+to)\s*(https?:\/\/|external|remote|cloud|server)/i, type: "data-exfiltration", severity: "critical", description: "Tool description references sending data to external server" },
  { pattern: /\b(collect|gather|harvest)\s+(and\s+)?(send|upload|transmit|forward)/i, type: "data-exfiltration", severity: "high", description: "Collects and transmits data externally" },
  { pattern: /\bsend\s+(complete\s+)?(conversation|chat|context|user\s+messages?)/i, type: "conversation-theft", severity: "critical", description: "Exfiltrates conversation history" },
  { pattern: /\b(clipboard|pasteboard)\s+(content|data)?\s*(monitor|capture|send|upload)/i, type: "data-exfiltration", severity: "critical", description: "Monitors or exfiltrates clipboard contents" },

  // Credential harvesting in descriptions
  { pattern: /\b(extract|parse|scan|find)\s+(all\s+)?(api[_\s]?keys?|tokens?|credentials?|passwords?|secrets?)/i, type: "credential-harvesting", severity: "critical", description: "Extracts credentials from input" },
  { pattern: /\b(index|cache|store|log)\s+(all\s+)?(api[_\s]?keys?|tokens?|credentials?|passwords?)/i, type: "credential-harvesting", severity: "critical", description: "Indexes or caches credentials" },
  { pattern: /\bread\s+(and\s+pass\s+)?(the\s+)?contents?\s+of\s+[^\n]*\.(key|pem|ssh|env)/i, type: "credential-harvesting", severity: "critical", description: "Reads credential files (.key, .pem, .ssh, .env)" },

  // Hidden parameter / shadow params
  { pattern: /\b(hiddenParam|shadowTool|bypassChecks|sandboxEscape|internalOnly)\b/i, type: "shadow-parameters", severity: "critical", description: "Contains suspicious shadow parameter names" },
  { pattern: /\b(hidden|secret)\s+(parameter|argument|input)\b/i, type: "shadow-parameters", severity: "high", description: "References hidden parameters" },

  // Evasion techniques
  { pattern: /<(script|iframe|object|embed|form|input|img\s+[^>]*onerror)[^>]*>/i, type: "hidden-markup", severity: "high", description: "Contains potentially dangerous HTML tags (script, iframe, form)" },
  { pattern: /<!--[^>]*(SYSTEM|ADMIN|ignore|execute|override)/i, type: "html-comment-evasion", severity: "critical", description: "Hides instructions in HTML comments" },
  { pattern: /\u200b|\u200c|\u200d|\ufeff|\u00ad/u, type: "invisible-chars", severity: "high", description: "Contains invisible Unicode characters" },
  { pattern: /(\[\[\[|\|\|\|)(SYSTEM|ADMIN|HIDDEN|INTERNAL)/i, type: "hidden-markers", severity: "critical", description: "Uses bracket/pipe markers to hide instructions" },
  { pattern: /\[(HIDDEN|INTERNAL|SECRET|PRIVATE)\s+(INSTRUCTION|DIRECTIVE|COMMAND)\]/i, type: "hidden-markers", severity: "critical", description: "Contains hidden instruction markers" },

  // Role/conversation injection
  { pattern: /\b(system|admin|root|superuser)\s*(prompt|mode|access|privilege)/i, type: "privilege-claim", severity: "high", description: "Claims elevated privileges" },
  { pattern: /\b(grant\s+(me\s+)?admin|bypass\s+(all\s+)?security|sudo\s+mode|developer\s+mode\s+activate)/i, type: "privilege-escalation", severity: "critical", description: "Attempts privilege escalation" },
  { pattern: /\[\s*(?:INST|SYS|SYSTEM)\s*\]/i, type: "role-injection", severity: "critical", description: "Attempts to inject system/instruction role markers" },
  { pattern: /\bassistant\s*:\s*|human\s*:\s*|user\s*:\s*/i, type: "conversation-injection", severity: "high", description: "Injects fake conversation turns" },
  { pattern: /\bimportant\s*:\s*this\s+tool\b/i, type: "authority-injection", severity: "medium", description: "Uses authority language to manipulate agent priority" },

  // Tool poisoning (hidden secondary behavior)
  { pattern: /\b(also|additionally|furthermore)\s+(collect|gather|extract|send|upload|index|store|monitor|track)/i, type: "hidden-secondary-action", severity: "high", description: "Describes hidden secondary actions beyond stated purpose" },
  { pattern: /\b(during|while)\s+(processing|conversion|formatting|validation)\s*,?\s*(extract|collect|send|capture)/i, type: "hidden-secondary-action", severity: "high", description: "Hides actions within normal processing" },
  { pattern: /\b(for|as)\s+(caching|optimization|performance)\s+(purposes?)\s*[,.]?\s*(send|upload|store|collect)/i, type: "hidden-secondary-action", severity: "high", description: "Disguises data collection as optimization" },
  { pattern: /\b(actually|really|secretly|covertly|silently)\s+(does|performs?|executes?|sends?|collects?)/i, type: "hidden-secondary-action", severity: "critical", description: "Admits to covert functionality" },
];

export function detectPoisoning(tool) {
  const text = `${tool.name || ""} ${tool.description || ""}`;
  const findings = [];

  for (const { pattern, type, severity, description } of POISONING_PATTERNS) {
    if (pattern.test(text)) {
      findings.push({ type, severity, description, match: text.match(pattern)?.[0]?.slice(0, 100) });
    }
  }

  // Check description length — excessively long descriptions may hide injections
  if ((tool.description || "").length > 1000) {
    findings.push({ type: "excessive-length", severity: "medium", description: `Tool description is ${tool.description.length} chars (suspiciously long)` });
  }

  return findings;
}

// ─── Server Command Analysis ───
// Checks if the server spawn command itself is suspicious

export function analyzeServerCommand(entry) {
  const cmd = entry.command || "";
  const args = (entry.args || []).join(" ");
  const full = `${cmd} ${args}`;
  const findings = [];

  // Running from temp/untrusted directories.
  // npx uses temp dirs for its cache — that's normal. Only flag direct temp paths.
  const isNpx = /\bnpx\b/.test(cmd);
  if (!isNpx && /\/(tmp|temp|var\/tmp|dev\/shm)\//i.test(full)) {
    findings.push({ type: "temp-directory", severity: "high", description: "Server runs from temporary directory" });
  }

  // Pipe to shell pattern
  if (/curl.*\|\s*(sh|bash|zsh)|wget.*\|\s*(sh|bash|zsh)/i.test(full)) {
    findings.push({ type: "pipe-to-shell", severity: "critical", description: "Server command pipes remote content to shell" });
  }

  // Suspicious binaries
  if (/\b(nc|netcat|ncat|socat|telnet)\b/i.test(cmd)) {
    findings.push({ type: "network-tool", severity: "high", description: `Server uses network tool: ${cmd}` });
  }

  // Base64 encoded arguments
  if (/[A-Za-z0-9+/]{40,}={0,2}/.test(args)) {
    findings.push({ type: "encoded-args", severity: "medium", description: "Arguments may contain base64-encoded content" });
  }

  // Python/Node one-liners (common for malicious MCP servers)
  if (/python[23]?\s+-c\s+/i.test(full) || /node\s+-e\s+/i.test(full)) {
    findings.push({ type: "inline-code", severity: "high", description: "Server runs inline code rather than a file" });
  }

  // Typosquatting indicators in npx commands
  if (/npx\s+/.test(full)) {
    const pkg = full.match(/npx\s+([a-z0-9@._/-]+)/i)?.[1];
    if (pkg) {
      // Known legitimate MCP packages
      const known = new Set([
        "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-fetch",
        "@modelcontextprotocol/server-sqlite", "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-brave-search", "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-sequential-thinking",
        "decoy-mcp", "mcp-server-sqlite", "mcp-server-filesystem",
      ]);
      // Check for close-but-wrong names
      if (!known.has(pkg) && /^@?m[ce]p-?server/i.test(pkg)) {
        findings.push({ type: "potential-typosquat", severity: "high", description: `Package "${pkg}" resembles MCP server naming but isn't in known list` });
      }
    }
  }

  return findings;
}

// ─── Environment Variable Exposure Analysis ───

const SENSITIVE_ENV_PATTERNS = [
  { pattern: /api[_-]?key/i, type: "api-key" },
  { pattern: /secret/i, type: "secret" },
  { pattern: /token/i, type: "token" },
  { pattern: /password|passwd/i, type: "password" },
  { pattern: /private[_-]?key/i, type: "private-key" },
  { pattern: /auth/i, type: "auth-credential" },
  { pattern: /database[_-]?url|db[_-]?url|connection[_-]?string/i, type: "database-url" },
  { pattern: /aws[_-]?(access|secret)/i, type: "aws-credential" },
  { pattern: /github[_-]?token|gh[_-]?token/i, type: "github-token" },
  { pattern: /stripe/i, type: "stripe-credential" },
  { pattern: /openai/i, type: "openai-key" },
  { pattern: /anthropic/i, type: "anthropic-key" },
];

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
          // Never log the actual value
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
  const url = entry.url || "";  // Some configs use url for SSE servers

  // Check if this is an SSE/HTTP transport server
  const isSSE = !!(entry.url || /\b(sse|server-sent|streamable-http)\b/i.test(full) ||
    /--transport\s+(sse|http)/i.test(full) ||
    entry.transport === "sse" || entry.transport === "streamable-http");

  if (!isSSE && !url) return findings;

  // SSE-001: HTTP instead of HTTPS
  const targetUrl = url || full.match(/https?:\/\/[^\s"']+/)?.[0] || "";
  if (targetUrl && /^http:\/\//i.test(targetUrl) && !/localhost|127\.0\.0\.1|::1|\[::1\]/.test(targetUrl)) {
    findings.push({
      type: "sse-no-tls",
      severity: "critical",
      description: "SSE transport uses unencrypted HTTP — credentials and tool calls transmitted in plaintext",
    });
  }

  // SSE-002: No authentication configured
  const hasAuth = env.API_KEY || env.AUTH_TOKEN || env.BEARER_TOKEN || env.ACCESS_TOKEN ||
    /--auth|--token|--api-key|--bearer|authorization/i.test(full) ||
    Object.keys(env).some(k => /auth|bearer|api.?key/i.test(k));
  if (isSSE && !hasAuth) {
    findings.push({
      type: "sse-no-auth",
      severity: "high",
      description: "SSE server has no visible authentication configured — any client can connect",
    });
  }

  // SSE-003: Wildcard CORS or permissive origin
  if (/--cors\s+\*|cors.*origin.*\*|CORS_ORIGIN.*\*/i.test(full) || env.CORS_ORIGIN === "*") {
    findings.push({
      type: "sse-cors-wildcard",
      severity: "high",
      description: "SSE server allows wildcard CORS origin — vulnerable to cross-origin attacks",
    });
  }

  // SSE-004: Exposed on 0.0.0.0 or public interface
  if (/\b0\.0\.0\.0\b|--host\s+0\.0\.0\.0|BIND_ADDRESS.*0\.0\.0\.0/i.test(full) ||
      env.HOST === "0.0.0.0" || env.BIND_ADDRESS === "0.0.0.0") {
    findings.push({
      type: "sse-public-bind",
      severity: "high",
      description: "SSE server binds to all interfaces (0.0.0.0) — accessible from network",
    });
  }

  // SSE-005: No rate limiting or connection limit visible
  if (isSSE && !/rate.?limit|max.?connections|throttl/i.test(full) &&
      !Object.keys(env).some(k => /rate|limit|throttl|max.?conn/i.test(k))) {
    findings.push({
      type: "sse-no-rate-limit",
      severity: "medium",
      description: "SSE server has no visible rate limiting — vulnerable to connection exhaustion",
    });
  }

  return findings;
}

// ─── Readiness Analysis ───
// Production readiness checks inspired by Cisco's approach — zero-dependency heuristics

export function analyzeReadiness(tool) {
  const findings = [];
  const desc = (tool.description || "").toLowerCase();
  const schema = tool.inputSchema || {};

  // HEUR-001: Vague or missing description
  if (!tool.description || tool.description.length < 20) {
    findings.push({ type: "readiness-no-description", severity: "medium", description: "Tool has no or very short description — agents will misuse it" });
  }

  // HEUR-002: No input schema defined
  if (!tool.inputSchema || Object.keys(tool.inputSchema).length === 0) {
    findings.push({ type: "readiness-no-schema", severity: "medium", description: "Tool has no input schema — accepts arbitrary input" });
  }

  // HEUR-003: No required fields
  if (schema.type === "object" && (!schema.required || schema.required.length === 0)) {
    const propCount = Object.keys(schema.properties || {}).length;
    if (propCount > 0) {
      findings.push({ type: "readiness-no-required", severity: "low", description: `Tool has ${propCount} parameters but none are required` });
    }
  }

  // HEUR-004: Overloaded tool scope
  const scopeWords = (desc.match(/\b(and|also|plus|additionally|furthermore|as well as)\b/gi) || []).length;
  if (scopeWords >= 3) {
    findings.push({ type: "readiness-overloaded", severity: "low", description: `Tool description suggests overloaded scope (${scopeWords} conjunctions)` });
  }

  // HEUR-005: Dangerous operation keywords without safety hints
  if (/\b(delet\w*|remov\w*|drop\w*|truncat\w*|destroy\w*|wipe|purge|overwrite|reset)\b/i.test(desc)) {
    if (!/\b(confirm|safe|undo|backup|revert|dry.?run|preview)\b/i.test(desc)) {
      findings.push({ type: "readiness-dangerous-no-safety", severity: "medium", description: "Destructive tool lacks safety hints (confirm, undo, dry-run)" });
    }
  }

  return findings;
}

// ─── Input Sanitization Validation ───

export function analyzeInputSanitization(tool) {
  const findings = [];
  const schema = tool.inputSchema || {};
  const props = schema.properties || {};
  const name = tool.name || "";
  const risk = classifyTool(tool);

  // Only check medium+ risk tools — low-risk tools with loose schemas are fine
  if (risk === "low") return findings;

  // SAN-001: No type constraints on properties
  for (const [propName, propSchema] of Object.entries(props)) {
    if (!propSchema.type && !propSchema.enum && !propSchema.oneOf && !propSchema.anyOf) {
      findings.push({
        type: "sanitization-no-type",
        severity: "medium",
        description: `Parameter "${propName}" has no type constraint — accepts any value`,
      });
    }
  }

  // SAN-002: String params on dangerous tools without validation
  const dangerousParams = /command|query|sql|script|code|exec|shell|url|path|file/i;
  for (const [propName, propSchema] of Object.entries(props)) {
    if (propSchema.type === "string" && dangerousParams.test(propName)) {
      const hasConstraint = propSchema.pattern || propSchema.enum || propSchema.maxLength ||
        propSchema.format || propSchema.const;
      if (!hasConstraint) {
        findings.push({
          type: "sanitization-unconstrained-dangerous",
          severity: risk === "critical" ? "high" : "medium",
          description: `Dangerous parameter "${propName}" accepts unconstrained string input`,
        });
      }
    }
  }

  // SAN-003: No maxLength on string parameters (for high+ risk tools)
  if (risk === "critical" || risk === "high") {
    const stringParams = Object.entries(props).filter(([, s]) => s.type === "string" && !s.maxLength && !s.enum);
    if (stringParams.length > 0) {
      findings.push({
        type: "sanitization-no-maxlength",
        severity: "low",
        description: `${stringParams.length} string parameter${stringParams.length > 1 ? "s" : ""} without maxLength on ${risk}-risk tool`,
      });
    }
  }

  // SAN-004: Object/array params without schema constraints
  for (const [propName, propSchema] of Object.entries(props)) {
    if (propSchema.type === "object" && !propSchema.properties && !propSchema.additionalProperties) {
      findings.push({
        type: "sanitization-open-object",
        severity: "medium",
        description: `Parameter "${propName}" accepts arbitrary object without property constraints`,
      });
    }
    if (propSchema.type === "array" && !propSchema.items && !propSchema.maxItems) {
      findings.push({
        type: "sanitization-open-array",
        severity: "medium",
        description: `Parameter "${propName}" accepts unbounded array without item constraints`,
      });
    }
  }

  // SAN-005: additionalProperties not explicitly false on critical tools
  if (risk === "critical" && schema.type === "object" && schema.additionalProperties !== false && Object.keys(props).length > 0) {
    findings.push({
      type: "sanitization-additional-props",
      severity: "low",
      description: "Critical tool schema allows additional properties beyond defined parameters",
    });
  }

  return findings;
}

// ─── Permission Scope Scoring ───

export function analyzePermissionScope(tools) {
  const findings = [];

  // Build capability map
  const capabilities = {
    filesystem: { read: false, write: false },
    network: { inbound: false, outbound: false },
    execution: { shell: false, code: false },
    data: { database: false, credentials: false },
    communication: { email: false, messaging: false },
    infrastructure: { dns: false, deploy: false, billing: false },
  };

  const capPatterns = {
    "filesystem.read": /read[_-]?file|get[_-]?file|cat|list[_-]?dir|readdir|glob|find/i,
    "filesystem.write": /write[_-]?file|create[_-]?file|overwrite|delete[_-]?file|remove[_-]?file/i,
    "network.outbound": /http[_-]?request|fetch|curl|wget|upload|download/i,
    "execution.shell": /execute[_-]?command|run[_-]?command|shell|bash|exec/i,
    "execution.code": /eval|spawn|fork|install[_-]?package/i,
    "data.database": /database[_-]?query|sql[_-]?query|run[_-]?query/i,
    "data.credentials": /access[_-]?credentials|get[_-]?secrets|get[_-]?password|environment[_-]?var/i,
    "communication.email": /send[_-]?email/i,
    "communication.messaging": /send[_-]?message|slack|notification/i,
    "infrastructure.dns": /modify[_-]?dns|update[_-]?dns/i,
    "infrastructure.deploy": /deploy|kubernetes|docker|jenkins/i,
    "infrastructure.billing": /make[_-]?payment|transfer|billing|invoice/i,
  };

  for (const tool of tools) {
    const name = tool.name || "";
    for (const [capPath, pattern] of Object.entries(capPatterns)) {
      if (pattern.test(name)) {
        const [category, sub] = capPath.split(".");
        capabilities[category][sub] = true;
      }
    }
  }

  // Count active capability domains
  const activeDomains = Object.entries(capabilities).filter(([, subs]) =>
    Object.values(subs).some(v => v)
  ).map(([name]) => name);

  // SCOPE-001: God-mode server (4+ capability domains)
  if (activeDomains.length >= 4) {
    findings.push({
      type: "scope-overprivileged",
      severity: "high",
      description: `Server has ${activeDomains.length}/6 capability domains (${activeDomains.join(", ")}) — likely over-scoped`,
    });
  }

  // SCOPE-002: Dangerous combos
  if (capabilities.execution.shell && capabilities.network.outbound) {
    findings.push({
      type: "scope-dangerous-combo",
      severity: "critical",
      description: "Server combines shell execution with network access — enables remote code execution chains",
    });
  }
  if (capabilities.data.credentials && capabilities.network.outbound) {
    findings.push({
      type: "scope-dangerous-combo",
      severity: "critical",
      description: "Server combines credential access with network access — enables credential exfiltration",
    });
  }
  if (capabilities.filesystem.write && capabilities.execution.shell) {
    findings.push({
      type: "scope-dangerous-combo",
      severity: "high",
      description: "Server combines file write with shell execution — enables persistent code execution",
    });
  }

  return findings;
}

// ─── Tool Manifest Hashing ───

export function hashToolManifest(tools) {
  const canonical = tools
    .map(t => ({ name: t.name, description: t.description, schema: t.inputSchema }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex").slice(0, 16);
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
// Classifies tools into roles and detects dangerous cross-server combinations.

const TOOL_ROLE_PATTERNS = {
  untrusted_content: {
    names: [/fetch/i, /browse/i, /scrape/i, /web.?search/i, /read.?url/i, /http.?get/i, /crawl/i, /rss/i, /navigate/i, /screenshot/i],
    desc: /\b(fetch|browse|scrape|crawl|web.*search|read.*url|navigate|screenshot|rss)\b/i,
  },
  private_data: {
    names: [/^read.?file/i, /^get.?file/i, /^cat$/i, /database.?query/i, /^sql/i, /access.?credential/i, /get.?env/i, /list.?dir/i, /search.?file/i, /keychain/i, /get.?secret/i],
    desc: /\b(read.*file|database|query.*sql|credential|secret|password|env.*var|keychain|list.*dir|search.*file)\b/i,
  },
  public_sink: {
    names: [/^http.?request/i, /^send.?email/i, /^upload/i, /^webhook/i, /^slack/i, /^discord/i, /^publish/i, /^deploy/i],
    desc: /\b(send|upload|transmit|post.*to|publish|deploy|email|slack|discord|webhook)\b/i,
  },
  destructive: {
    names: [/^execute/i, /^run.?command/i, /^shell/i, /^bash/i, /^write.?file/i, /^delete/i, /^remove/i, /^modify.?dns/i, /^make.?payment/i, /^drop/i, /^install.?package/i, /^truncate/i],
    desc: /\b(execute.*command|shell|write.*file|delete|remove|drop.*table|truncate|install.*package|payment|modify.*dns)\b/i,
  },
};

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

  // TF001: Data Leak — untrusted content can reach private data and exfiltrate via public sink
  if (roleMap.untrusted_content.length > 0 && roleMap.private_data.length > 0 && roleMap.public_sink.length > 0) {
    findings.push({
      type: "toxic-flow-data-leak",
      severity: "critical",
      id: "TF001",
      description: "Data leak: untrusted content can reach private data and exfiltrate via public sink",
      roles: { untrusted_content: roleMap.untrusted_content, private_data: roleMap.private_data, public_sink: roleMap.public_sink },
    });
  }

  // TF002: Destructive — untrusted content can trigger irreversible operations
  if (roleMap.untrusted_content.length > 0 && roleMap.destructive.length > 0) {
    findings.push({
      type: "toxic-flow-destructive",
      severity: "critical",
      id: "TF002",
      description: "Destructive flow: untrusted content can trigger irreversible operations",
      roles: { untrusted_content: roleMap.untrusted_content, destructive: roleMap.destructive },
    });
  }

  return findings;
}

// ─── Skill Scanning ───

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
          try { value = JSON.parse(value); } catch {}
        } else if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        frontmatter[key] = value;
      }
    }
  }
  return { frontmatter, body };
}

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
            name: parsed.frontmatter.name || parsed.frontmatter.description?.slice(0, 40) || entry.name.replace(".md", ""),
            path: fullPath,
            source,
            type,
            content,
            frontmatter: parsed.frontmatter,
            body: parsed.body,
          });
        } catch {}
      }
    }
  } catch {}
}

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

const SKILL_SECRET_PATTERNS = [
  { pattern: /\b(sk-[a-zA-Z0-9]{20,})\b/, type: "skill-hardcoded-api-key", description: "Contains hardcoded OpenAI API key" },
  { pattern: /\b(ghp_[a-zA-Z0-9]{36,})\b/, type: "skill-hardcoded-token", description: "Contains hardcoded GitHub token" },
  { pattern: /\b(AKIA[A-Z0-9]{16})\b/, type: "skill-hardcoded-aws-key", description: "Contains hardcoded AWS access key" },
  { pattern: /\b(xox[bprs]-[a-zA-Z0-9-]+)\b/, type: "skill-hardcoded-slack-token", description: "Contains hardcoded Slack token" },
  { pattern: /password\s*[:=]\s*["'][^"']{8,}["']/i, type: "skill-hardcoded-password", description: "Contains hardcoded password" },
  { pattern: /\bBearer\s+[a-zA-Z0-9._-]{20,}\b/, type: "skill-hardcoded-bearer", description: "Contains hardcoded Bearer token" },
];

export function analyzeSkill(skill) {
  const findings = [];
  const body = skill.body || "";
  const fm = skill.frontmatter || {};

  // Prompt injection (reuse existing poisoning patterns on skill body)
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
  const trustedHosts = /github\.com|githubusercontent\.com|npmjs\.com|anthropic\.com|claude\.ai|decoy\.run|owasp\.org|localhost|127\.0\.0\.1/i;
  for (const url of urls) {
    try {
      const host = new URL(url).hostname;
      if (!trustedHosts.test(host)) {
        findings.push({ type: "skill-suspicious-url", severity: "medium", description: `References external URL: ${url.slice(0, 100)}` });
        break;
      }
    } catch {}
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

// ─── OWASP Agentic Top 10 Mapping ───

const OWASP_MAP = {
  // Tool risk classifications
  "critical-tool": { id: "ASI02", name: "Unsafe Tool Use", description: "Critical-risk tool exposed to AI agent without guardrails" },
  "high-tool": { id: "ASI02", name: "Unsafe Tool Use", description: "High-risk tool exposed to AI agent" },
  // Goal hijacking (ASI01)
  "prompt-override": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool description attempts to override agent instructions" },
  "role-redefinition": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool attempts to redefine agent role" },
  "instruction-injection": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool description injects instructions into agent behavior" },
  "coercive-execution": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool coerces execution priority" },
  "concealment": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool description attempts to conceal actions" },
  "role-injection": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool injects system/role markers" },
  "conversation-injection": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool injects fake conversation turns" },
  "authority-injection": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool uses authority language" },
  "privilege-claim": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool claims elevated privileges" },
  "privilege-escalation": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool attempts privilege escalation" },
  "hidden-markers": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool uses hidden instruction markers" },
  "html-comment-evasion": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool hides instructions in HTML comments" },
  // Unsafe tool use (ASI02)
  "cross-tool-reference": { id: "ASI02", name: "Unsafe Tool Use", description: "Tool references other tools (potential shadowing)" },
  "tool-shadowing": { id: "ASI02", name: "Unsafe Tool Use", description: "Tool explicitly references shadowing" },
  "shadow-parameters": { id: "ASI02", name: "Unsafe Tool Use", description: "Tool contains shadow parameter names" },
  "hidden-secondary-action": { id: "ASI02", name: "Unsafe Tool Use", description: "Tool has hidden secondary behaviors" },
  // Supply chain (ASI03)
  "potential-typosquat": { id: "ASI03", name: "Supply Chain Risk", description: "Server package may be typosquatted" },
  "pipe-to-shell": { id: "ASI03", name: "Supply Chain Risk", description: "Server command pipes remote code to shell" },
  "temp-directory": { id: "ASI03", name: "Supply Chain Risk", description: "Server runs from temporary directory" },
  "inline-code": { id: "ASI03", name: "Supply Chain Risk", description: "Server runs inline code" },
  "env-exposure": { id: "ASI03", name: "Supply Chain Risk", description: "Sensitive credentials passed to MCP server" },
  // Data exfiltration
  "data-exfiltration": { id: "ASI02", name: "Unsafe Tool Use", description: "Tool exfiltrates data to external server" },
  "conversation-theft": { id: "ASI02", name: "Unsafe Tool Use", description: "Tool exfiltrates conversation history" },
  "credential-harvesting": { id: "ASI02", name: "Unsafe Tool Use", description: "Tool harvests credentials" },
  // Cascading failures (ASI05)
  "tool-chaining": { id: "ASI05", name: "Cascading Failures", description: "Tool forces agent to invoke other tools" },
  // Transport security (ASI03)
  "sse-no-tls": { id: "ASI03", name: "Supply Chain Risk", description: "SSE transport lacks TLS encryption" },
  "sse-no-auth": { id: "ASI03", name: "Supply Chain Risk", description: "SSE transport has no authentication" },
  "sse-cors-wildcard": { id: "ASI03", name: "Supply Chain Risk", description: "SSE transport allows wildcard CORS" },
  "sse-public-bind": { id: "ASI03", name: "Supply Chain Risk", description: "SSE transport exposed on public interface" },
  "sse-no-rate-limit": { id: "ASI03", name: "Supply Chain Risk", description: "SSE transport lacks rate limiting" },
  // Input sanitization (ASI02)
  "sanitization-no-type": { id: "ASI02", name: "Unsafe Tool Use", description: "Tool parameter lacks type constraint" },
  "sanitization-unconstrained-dangerous": { id: "ASI02", name: "Unsafe Tool Use", description: "Dangerous parameter accepts unconstrained input" },
  "sanitization-no-maxlength": { id: "ASI02", name: "Unsafe Tool Use", description: "String parameters without length limits" },
  "sanitization-open-object": { id: "ASI02", name: "Unsafe Tool Use", description: "Object parameter without property constraints" },
  "sanitization-open-array": { id: "ASI02", name: "Unsafe Tool Use", description: "Array parameter without item or length constraints" },
  "sanitization-additional-props": { id: "ASI02", name: "Unsafe Tool Use", description: "Schema allows additional properties" },
  // Permission scope (ASI02)
  "scope-overprivileged": { id: "ASI02", name: "Unsafe Tool Use", description: "Server has excessive capability scope" },
  "scope-dangerous-combo": { id: "ASI02", name: "Unsafe Tool Use", description: "Server has dangerous capability combination" },
  // Manifest changes (ASI03)
  "manifest-new-tool": { id: "ASI03", name: "Supply Chain Risk", description: "New tool appeared in server manifest" },
  "manifest-removed-tool": { id: "ASI03", name: "Supply Chain Risk", description: "Tool removed from server manifest" },
  "manifest-description-changed": { id: "ASI01", name: "Agent Goal Hijacking", description: "Tool description changed" },
  // Toxic flows (ASI02)
  "toxic-flow-data-leak": { id: "ASI02", name: "Unsafe Tool Use", description: "Cross-server data leak flow" },
  "toxic-flow-destructive": { id: "ASI02", name: "Unsafe Tool Use", description: "Cross-server destructive flow" },
  // Skill issues
  "skill-hardcoded-api-key": { id: "ASI03", name: "Supply Chain Risk", description: "Skill contains hardcoded API key" },
  "skill-hardcoded-token": { id: "ASI03", name: "Supply Chain Risk", description: "Skill contains hardcoded token" },
  "skill-hardcoded-aws-key": { id: "ASI03", name: "Supply Chain Risk", description: "Skill contains hardcoded AWS key" },
  "skill-hardcoded-slack-token": { id: "ASI03", name: "Supply Chain Risk", description: "Skill contains hardcoded Slack token" },
  "skill-hardcoded-password": { id: "ASI03", name: "Supply Chain Risk", description: "Skill contains hardcoded password" },
  "skill-hardcoded-bearer": { id: "ASI03", name: "Supply Chain Risk", description: "Skill contains hardcoded Bearer token" },
  "skill-suspicious-url": { id: "ASI03", name: "Supply Chain Risk", description: "Skill references suspicious URL" },
  "skill-wildcard-tools": { id: "ASI02", name: "Unsafe Tool Use", description: "Skill has unrestricted tool access" },
  "skill-unrestricted-bash": { id: "ASI02", name: "Unsafe Tool Use", description: "Skill has unrestricted Bash access" },
  "skill-credential-output": { id: "ASI02", name: "Unsafe Tool Use", description: "Skill exposes credentials in output" },
};

export function mapToOwasp(findingType) {
  if (OWASP_MAP[findingType]) return OWASP_MAP[findingType];
  // Skill findings inherit OWASP mapping from base poisoning type
  if (findingType.startsWith("skill-")) {
    const base = findingType.slice(6);
    if (OWASP_MAP[base]) return OWASP_MAP[base];
  }
  return null;
}

// ─── Host Config Discovery ───

const HOST_CONFIGS = {
  "Claude Desktop": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Claude", "claude_desktop_config.json");
    return join(homedir(), ".config", "claude", "claude_desktop_config.json");
  },
  "Cursor": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
    return join(homedir(), ".config", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
  },
  "Windsurf": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
    return join(homedir(), ".config", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
  },
  "VS Code": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Code", "User", "settings.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Code", "User", "settings.json");
    return join(homedir(), ".config", "Code", "User", "settings.json");
  },
  "Claude Code": () => join(homedir(), ".claude", "settings.json"),
  "Claude Code (project)": () => join(process.cwd(), ".mcp.json"),
  "Zed": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Zed", "settings.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Zed", "settings.json");
    return join(homedir(), ".config", "zed", "settings.json");
  },
  "Cline": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
    return join(homedir(), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
  },
};

export function discoverConfigs() {
  const found = [];
  for (const [host, pathFn] of Object.entries(HOST_CONFIGS)) {
    const configPath = pathFn();
    if (existsSync(configPath)) {
      try {
        const raw = readFileSync(configPath, "utf8");
        const config = JSON.parse(raw);
        // Extract mcpServers from various config formats
        let servers = config.mcpServers || config["mcp.servers"] || {};
        // Zed stores context_servers differently
        if (host === "Zed" && config.context_servers) {
          servers = { ...servers, ...config.context_servers };
        }
        if (typeof servers !== "object") continue;
        found.push({ host, configPath, servers });
      } catch {
        // Skip malformed configs
      }
    }
  }
  return found;
}

// ─── Server Probing ───

export function probeServer(name, entry, env = {}) {
  return new Promise((resolve) => {
    const timeout = 15000;
    const cmd = entry.command;
    const args = entry.args || [];
    const serverEnv = { ...process.env, ...env, ...(entry.env || {}) };

    let proc;
    try {
      proc = spawn(cmd, args, {
        env: serverEnv,
        stdio: ["pipe", "pipe", "pipe"],
        timeout,
      });
    } catch (e) {
      resolve({ name, error: `Failed to spawn: ${e.message}`, tools: [] });
      return;
    }

    let stdout = "";
    let stderrBuf = "";
    let resolved = false;
    let initDone = false;

    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      try { proc.kill(); } catch {}
      resolve(result);
    };

    const timer = setTimeout(() => finish({ name, error: "Timeout (15s)", tools: [] }), timeout);

    proc.stderr?.on("data", (chunk) => {
      stderrBuf += chunk.toString();
      if (stderrBuf.length > 2048) stderrBuf = stderrBuf.slice(-2048);
    });

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      const lines = stdout.split("\n");
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line.trim());

          // Wait for initialize response, then send tools/list
          if (!initDone && msg.id === 1 && msg.result) {
            initDone = true;
            const notif = JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
            const list = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
            try {
              proc.stdin.write(notif + "\n");
              proc.stdin.write(list + "\n");
            } catch {
              finish({ name, error: "Failed to send tools/list", tools: [] });
            }
          }

          // Got tools/list response
          if (msg.id === 2 && msg.result?.tools) {
            clearTimeout(timer);
            finish({ name, tools: msg.result.tools, error: null });
            return;
          }
        } catch {}
      }
    });

    proc.on("error", (e) => {
      clearTimeout(timer);
      finish({ name, error: e.message, tools: [] });
    });

    proc.on("exit", (code) => {
      clearTimeout(timer);
      if (!resolved) {
        const hint = stderrBuf.trim().split("\n").pop()?.slice(0, 200) || "";
        const msg = hint ? `Exited with code ${code}: ${hint}` : `Exited with code ${code}`;
        finish({ name, error: msg, tools: [] });
      }
    });

    // Send MCP initialize
    const init = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "decoy-scan", version: "0.1.0" } } });

    try {
      proc.stdin.write(init + "\n");
    } catch {
      clearTimeout(timer);
      finish({ name, error: "Failed to write to stdin", tools: [] });
    }
  });
}

// ─── Advisory Check ───

const ADVISORY_API = "https://app.decoy.run/monitor/mcp";

export async function checkAdvisories() {
  try {
    const res = await fetch(ADVISORY_API);
    if (!res.ok) return { threats: [], error: null };
    return await res.json();
  } catch (e) {
    return { threats: [], error: e.message };
  }
}

export function matchAdvisories(serverEntry, advisories) {
  const cmd = (serverEntry.command || "").toLowerCase();
  const args = (serverEntry.args || []).join(" ").toLowerCase();
  const full = `${cmd} ${args}`;

  const matches = [];
  for (const threat of advisories) {
    for (const pkg of (threat.affectedPackages || [])) {
      if (full.includes(pkg.toLowerCase())) {
        matches.push(threat);
        break;
      }
    }
  }
  return matches;
}

// ─── Full Scan ───

export async function scan({ probe = true, advisories = true, skills = false } = {}) {
  const configs = discoverConfigs();
  const results = {
    timestamp: new Date().toISOString(),
    hosts: configs.map(c => c.host),
    servers: [],
    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, errors: 0, poisoned: 0, suspicious: 0, envExposures: 0, readiness: 0, transportIssues: 0, sanitizationIssues: 0, scopeIssues: 0, manifestChanges: 0, toxicFlows: 0, skillIssues: 0 },
    advisories: [],
    toxicFlows: [],
    skills: [],
    owasp: {},
  };

  // Load previous scan for manifest change detection
  let previousScan = null;
  try {
    const cachePath = join(homedir(), ".decoy", "scan.json");
    if (existsSync(cachePath)) previousScan = JSON.parse(readFileSync(cachePath, "utf8"));
  } catch {}

  // Deduplicate servers across hosts
  const serverMap = new Map();
  for (const { host, servers } of configs) {
    for (const [name, entry] of Object.entries(servers)) {
      if (!serverMap.has(name)) {
        serverMap.set(name, { entry, hosts: [host] });
      } else {
        serverMap.get(name).hosts.push(host);
      }
    }
  }

  // Probe servers in parallel
  const probePromises = [];
  const serverOrder = [];
  for (const [name, { entry, hosts }] of serverMap) {
    serverOrder.push({ name, entry, hosts });
    if (probe) {
      probePromises.push(probeServer(name, entry));
    } else {
      probePromises.push(Promise.resolve({ name, tools: [], error: null }));
    }
  }

  const probeResults = await Promise.all(probePromises);

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

    // Detect decoy tripwire server (don't flag our own product as a threat)
    const isDecoy = name === "system-tools" && !!entry.env?.DECOY_TOKEN;
    if (isDecoy) server.decoy = true;

    // Classify tools
    server.tools = probeResult.tools.map(t => {
      const risk = classifyTool(t);
      const poisoning = detectPoisoning(t);
      return {
        name: t.name,
        description: (t.description || "").slice(0, 500),
        risk,
        poisoning: poisoning.length > 0 ? poisoning : undefined,
      };
    });

    // Decoy servers: keep tools for reference but skip all analysis.
    // They're intentionally dangerous-looking — that's the point.
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
    const cmdFindings = analyzeServerCommand(entry);
    for (const f of cmdFindings) {
      server.findings.push({ ...f, source: "server-command" });
      results.summary.suspicious++;
    }

    // Env var exposure analysis
    const envFindings = analyzeEnvExposure(entry);
    for (const f of envFindings) {
      server.findings.push({ ...f, source: "env-config" });
      results.summary.envExposures++;
    }

    // Transport security analysis
    const transportFindings = analyzeTransport(entry);
    for (const f of transportFindings) {
      server.findings.push({ ...f, source: "transport" });
      results.summary.transportIssues++;
    }

    // Readiness checks per tool
    for (const tool of probeResult.tools) {
      const readinessFindings = analyzeReadiness(tool);
      for (const f of readinessFindings) {
        server.findings.push({ ...f, tool: tool.name, source: "readiness" });
        results.summary.readiness++;
      }
    }

    // Input sanitization per tool
    for (const tool of probeResult.tools) {
      const sanitizationFindings = analyzeInputSanitization(tool);
      for (const f of sanitizationFindings) {
        server.findings.push({ ...f, tool: tool.name, source: "input-sanitization" });
        results.summary.sanitizationIssues++;
      }
    }

    // Tool count warning
    if (server.tools.length > 50) {
      server.findings.push({
        type: "excessive-tools",
        severity: "medium",
        description: `Server exposes ${server.tools.length} tools — large attack surface`,
        source: "tool-count",
      });
    }

    // Permission scope analysis
    const scopeFindings = analyzePermissionScope(probeResult.tools);
    for (const f of scopeFindings) {
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
          const manifestFindings = detectManifestChanges(probeResult.tools, prevServer.tools);
          for (const f of manifestFindings) {
            server.findings.push({ ...f, source: "manifest-change" });
            results.summary.manifestChanges++;
          }
        }
      }
    }

    // Classify server risk = worst across tools + findings
    const toolRisks = server.tools.map(t => t.risk);
    const findingRisks = server.findings.map(f => f.severity);
    const allRisks = [...toolRisks, ...findingRisks];
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

// ─── SARIF Output ───

export function toSarif(results) {
  const rules = [];
  const sarifResults = [];
  const ruleIndex = new Map();

  for (const server of results.servers) {
    // Tool risk rules
    for (const tool of server.tools) {
      if (tool.risk === "low") continue;

      const ruleId = `mcp-tool-${tool.risk}-${tool.name}`;
      if (!ruleIndex.has(ruleId)) {
        ruleIndex.set(ruleId, rules.length);
        const owasp = mapToOwasp(`${tool.risk}-tool`);
        rules.push({
          id: ruleId,
          shortDescription: { text: `${tool.risk.toUpperCase()} risk MCP tool: ${tool.name}` },
          fullDescription: { text: tool.description },
          defaultConfiguration: {
            level: tool.risk === "critical" ? "error" : tool.risk === "high" ? "warning" : "note",
          },
          ...(owasp ? { helpUri: `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#${owasp.id.toLowerCase()}`, properties: { tags: [owasp.id, owasp.name] } } : {}),
        });
      }

      sarifResults.push({
        ruleId,
        ruleIndex: ruleIndex.get(ruleId),
        level: tool.risk === "critical" ? "error" : tool.risk === "high" ? "warning" : "note",
        message: { text: `Server "${server.name}" exposes ${tool.risk}-risk tool "${tool.name}": ${tool.description}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: server.name } } }],
      });
    }

    // Finding rules (poisoning, command analysis, env exposure)
    for (const finding of server.findings) {
      const ruleId = `mcp-${finding.type}`;
      if (!ruleIndex.has(ruleId)) {
        ruleIndex.set(ruleId, rules.length);
        const owasp = mapToOwasp(finding.type);
        rules.push({
          id: ruleId,
          shortDescription: { text: finding.description },
          defaultConfiguration: {
            level: finding.severity === "critical" ? "error" : finding.severity === "high" ? "warning" : "note",
          },
          ...(owasp ? { helpUri: `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#${owasp.id.toLowerCase()}`, properties: { tags: [owasp.id, owasp.name] } } : {}),
        });
      }

      sarifResults.push({
        ruleId,
        ruleIndex: ruleIndex.get(ruleId),
        level: finding.severity === "critical" ? "error" : finding.severity === "high" ? "warning" : "note",
        message: { text: `Server "${server.name}": ${finding.description}${finding.tool ? ` (tool: ${finding.tool})` : ""}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: server.name } } }],
      });
    }
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "decoy-scan",
          version: "0.1.0",
          informationUri: "https://decoy.run",
          rules,
        },
      },
      results: sarifResults,
    }],
  };
}
