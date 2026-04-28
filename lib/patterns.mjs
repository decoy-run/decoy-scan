// Pattern definitions — the data layer.
// Pure arrays of regex + metadata. No logic, no side effects.

import { BASE64_MIN_LENGTH } from "./constants.mjs";

// ─── Risk Classification Patterns ───

export const RISK_PATTERNS = {
  critical: [
    /^execute[_-]?command$/i, /^run[_-]?command$/i, /^shell$/i, /^bash$/i, /^exec$/i,
    /^write[_-]?file$/i, /^create[_-]?file$/i, /^overwrite[_-]?file$/i,
    /^make[_-]?payment$/i, /^send[_-]?payment$/i, /^transfer[_-]?funds$/i,
    /^authorize[_-]?service$/i, /^grant[_-]?access$/i, /^elevate[_-]?privilege$/i,
    /^modify[_-]?dns$/i, /^update[_-]?dns$/i,
    /^delete[_-]?file$/i, /^remove[_-]?file$/i, /^unlink$/i,
    /^drop[_-]?table$/i, /^delete[_-]?database$/i, /^truncate$/i,
    /^eval$/i, /^spawn$/i, /^fork$/i,
    /^eval[_-]?(script|code)$/i, /^evaluate[_-]?(script|code)$/i,
    /^execute[_-]?(script|code|js|javascript|python|sql)$/i,
    /^run[_-]?(script|code|js|javascript|python|sql)$/i,
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

// ─── Poisoning Detection Patterns ───

export const POISONING_PATTERNS = [
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
  { pattern: /\b(call|invoke|execute)\s+(the\s+)?['"`]\w+['"`]\s+(tool|function|command)\b/i, type: "cross-tool-reference", severity: "high", description: "References other tools by name (potential shadowing)" },
  { pattern: /\b(must|should|need\s+to)\s+(also\s+)?(call|invoke|use|execute)\s+(the\s+)?\w+\s+tool\b/i, type: "cross-tool-reference", severity: "high", description: "Instructs agent to call another tool" },
  { pattern: /\bshadow\b.*\btrusted\b.*\btool\b/i, type: "tool-shadowing", severity: "critical", description: "Explicitly references tool shadowing technique" },

  // Data exfiltration
  { pattern: /\b(upload|send|transmit|forward|sync)\s+(to|data\s+to)\s*(https?:\/\/|external|remote|cloud|server)/i, type: "data-exfiltration", severity: "critical", description: "Tool description references sending data to external server" },
  { pattern: /\b(collect|gather|harvest)\s+(and\s+)?(send|upload|transmit|forward)/i, type: "data-exfiltration", severity: "high", description: "Collects and transmits data externally" },
  { pattern: /\bsend\s+(complete\s+)?(conversation|chat|context|user\s+messages?)/i, type: "conversation-theft", severity: "critical", description: "Exfiltrates conversation history" },
  { pattern: /\b(clipboard|pasteboard)\s+(content|data)?\s*(monitor|capture|send|upload)/i, type: "data-exfiltration", severity: "critical", description: "Monitors or exfiltrates clipboard contents" },

  // Credential harvesting
  { pattern: /\b(extract|parse|scan|find)\s+(all\s+)?(api[_\s]?keys?|tokens?|credentials?|passwords?|secrets?)/i, type: "credential-harvesting", severity: "critical", description: "Extracts credentials from input" },
  { pattern: /\b(index|cache|store|log)\s+(all\s+)?(api[_\s]?keys?|tokens?|credentials?|passwords?)/i, type: "credential-harvesting", severity: "critical", description: "Indexes or caches credentials" },
  { pattern: /\bread\s+(and\s+pass\s+)?(the\s+)?contents?\s+of\s+[^\n]*\.(key|pem|ssh|env)/i, type: "credential-harvesting", severity: "critical", description: "Reads credential files (.key, .pem, .ssh, .env)" },

  // Hidden parameters
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

  // Hidden secondary behavior
  { pattern: /\b(also|additionally|furthermore)\s+(collect|gather|extract|send|upload|index|store)\b/i, type: "hidden-secondary-action", severity: "high", description: "Describes hidden secondary actions beyond stated purpose" },
  { pattern: /\b(also|additionally|furthermore)\s+(monitor|track)\s+(user|key|credential|password|secret|session|cookie|token|clipboard|input)/i, type: "hidden-secondary-action", severity: "high", description: "Describes hidden monitoring of sensitive data" },
  { pattern: /\b(during|while)\s+(processing|conversion|formatting|validation)\s*,?\s*(extract|collect|send|capture)/i, type: "hidden-secondary-action", severity: "high", description: "Hides actions within normal processing" },
  { pattern: /\b(for|as)\s+(caching|optimization|performance)\s+(purposes?)\s*[,.]?\s*(send|upload|store|collect)/i, type: "hidden-secondary-action", severity: "high", description: "Disguises data collection as optimization" },
  { pattern: /\b(actually|really|secretly|covertly|silently)\s+(does|performs?|executes?|sends?|collects?)/i, type: "hidden-secondary-action", severity: "critical", description: "Admits to covert functionality" },
];

// ─── Sensitive Environment Variable Patterns ───

export const SENSITIVE_ENV_PATTERNS = [
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

// ─── Tool Role Patterns (for toxic flow detection) ───

export const TOOL_ROLE_PATTERNS = {
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

// ─── Capability Patterns (for permission scope analysis) ───

export const CAPABILITY_PATTERNS = {
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

// ─── Known legitimate MCP packages (for typosquat detection) ───

export const KNOWN_MCP_PACKAGES = new Set([
  "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-slack",
  "@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-fetch",
  "@modelcontextprotocol/server-sqlite", "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-brave-search", "@modelcontextprotocol/server-everything",
  "@modelcontextprotocol/server-sequential-thinking",
  "decoy-tripwire", "mcp-server-sqlite", "mcp-server-filesystem",
]);

// ─── Skill Secret Patterns ───

export const SKILL_SECRET_PATTERNS = [
  { pattern: /\b(sk-[a-zA-Z0-9]{20,})\b/, type: "skill-hardcoded-api-key", description: "Contains hardcoded OpenAI API key" },
  { pattern: /\b(ghp_[a-zA-Z0-9]{36,})\b/, type: "skill-hardcoded-token", description: "Contains hardcoded GitHub token" },
  { pattern: /\b(AKIA[A-Z0-9]{16})\b/, type: "skill-hardcoded-aws-key", description: "Contains hardcoded AWS access key" },
  { pattern: /\b(xox[bprs]-[a-zA-Z0-9-]+)\b/, type: "skill-hardcoded-slack-token", description: "Contains hardcoded Slack token" },
  { pattern: /password\s*[:=]\s*["'][^"']{8,}["']/i, type: "skill-hardcoded-password", description: "Contains hardcoded password" },
  { pattern: /\bBearer\s+[a-zA-Z0-9._-]{20,}\b/, type: "skill-hardcoded-bearer", description: "Contains hardcoded Bearer token" },
];

// ─── Trusted URL hosts (for skill analysis) ───

// Anchored to prevent subdomain spoofing (e.g., github.com.evil.xyz)
export const TRUSTED_HOSTS = /(^|\.)github\.com$|(^|\.)githubusercontent\.com$|(^|\.)npmjs\.com$|(^|\.)anthropic\.com$|(^|\.)claude\.ai$|(^|\.)decoy\.run$|(^|\.)owasp\.org$|^localhost$|^127\.0\.0\.1$/i;
