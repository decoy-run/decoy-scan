// Plan/tier resolution for the CLI. Looks up a token's plan via /api/billing
// and caches the answer at ~/.decoy/tier for 24 hours so each `explain` call
// doesn't take an extra network round-trip.
//
// Returns one of: "free" | "team" | "business" | "unknown".
// "unknown" means: no token, fetch failed, or response was malformed —
// callers should treat unknown as free for gating purposes.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const CACHE_FILE = join(homedir(), ".decoy", "tier");
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const TIMEOUT_MS = 4000;

const API_BASE = process.env.DECOY_API_BASE
  ? process.env.DECOY_API_BASE.replace(/\/+$/, "")
  : "https://app.decoy.run/api";

const PAID = new Set(["team", "pro", "business"]);

export function isPaidTier(tier) {
  return PAID.has(tier);
}

function readCache(token) {
  if (!existsSync(CACHE_FILE)) return null;
  try {
    const obj = JSON.parse(readFileSync(CACHE_FILE, "utf8"));
    if (!obj || typeof obj !== "object") return null;
    if (obj.token !== token) return null;
    if (typeof obj.cachedAt !== "number") return null;
    if (Date.now() - obj.cachedAt > CACHE_TTL_MS) return null;
    return obj.tier || null;
  } catch { return null; }
}

function writeCache(token, tier) {
  try {
    if (!existsSync(join(homedir(), ".decoy"))) mkdirSync(join(homedir(), ".decoy"), { recursive: true });
    writeFileSync(CACHE_FILE, JSON.stringify({ token, tier, cachedAt: Date.now() }), { mode: 0o600 });
  } catch { /* best-effort cache; ignore */ }
}

export async function resolveTier(token) {
  if (!token) return "unknown";
  const cached = readCache(token);
  if (cached) return cached;
  try {
    const res = await fetch(`${API_BASE}/billing?token=${encodeURIComponent(token)}`, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return "unknown";
    const data = await res.json();
    const tier = (data.plan || "free").toLowerCase();
    writeCache(token, tier);
    return tier;
  } catch {
    return "unknown";
  }
}
