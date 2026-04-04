// decoy-scan — MCP supply chain scanner
// Public API — re-exports from lib/ modules.

export { classifyTool, detectPoisoning, analyzeServerCommand, analyzeEnvExposure, analyzeTransport, analyzeReadiness, analyzeInputSanitization, analyzePermissionScope, hashToolManifest, detectManifestChanges, analyzeToxicFlows } from "./lib/analyzers.mjs";
export { discoverSkills, analyzeSkill } from "./lib/skills.mjs";
export { mapToOwasp } from "./lib/owasp.mjs";
export { discoverConfigs } from "./lib/discovery.mjs";
export { probeServer } from "./lib/probe.mjs";
export { checkAdvisories, matchAdvisories } from "./lib/advisories.mjs";
export { scan } from "./lib/scan.mjs";
export { toSarif } from "./lib/sarif.mjs";
