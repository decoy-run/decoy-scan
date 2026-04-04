// SARIF 2.1.0 output — exports scan results for GitHub Security tab and other SARIF consumers.

import { mapToOwasp } from "./owasp.mjs";
import { MCP_CLIENT_VERSION } from "./constants.mjs";

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

    // Finding rules
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
          version: MCP_CLIENT_VERSION,
          informationUri: "https://decoy.run",
          rules,
        },
      },
      results: sarifResults,
    }],
  };
}
