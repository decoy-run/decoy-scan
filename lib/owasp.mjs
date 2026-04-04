// OWASP Agentic Top 10 mapping — finding type → OWASP ID

const OWASP_MAP = {
  // Tool risk
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
  // Manifest changes (ASI03 / ASI01)
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
  if (findingType.startsWith("skill-")) {
    const base = findingType.slice(6);
    if (OWASP_MAP[base]) return OWASP_MAP[base];
  }
  return null;
}
