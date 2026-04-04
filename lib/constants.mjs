// Extracted constants — no more magic numbers at 3am

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8"));

// ─── Probe ───
export const PROBE_TIMEOUT_MS = 15_000;
export const STDERR_BUFFER_MAX = 2048;
export const STDERR_HINT_MAX = 200;

// ─── Tool analysis ───
export const MIN_DESCRIPTION_LENGTH = 20;
export const EXCESSIVE_DESCRIPTION_LENGTH = 1000;
export const OVERLOADED_SCOPE_THRESHOLD = 3;
export const GOD_MODE_DOMAIN_THRESHOLD = 4;
export const EXCESSIVE_TOOL_COUNT = 50;
export const TOOL_DESCRIPTION_SLICE = 500;

// ─── Hashing ───
export const MANIFEST_HASH_LENGTH = 16;

// ─── Detection thresholds ───
export const BASE64_MIN_LENGTH = 40;
export const POISONING_MATCH_SLICE = 100;

// ─── Skill scanning ───
export const SKILL_NAME_MAX = 40;

// ─── MCP protocol ───
export const MCP_PROTOCOL_VERSION = "2024-11-05";
export const MCP_CLIENT_VERSION = PKG.version;
