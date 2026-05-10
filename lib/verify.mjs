// Client for the /api/verify endpoint — DeepSec-style AI verification of
// scan findings. 5 free verifies / installId / month, unlimited on Team+.
//
// Returns:
//   { ok: true, verified: [...], stats: {...}, quota: {...} | null }
//   { ok: false, status, code, message, upgradeUrl?: string, quota?: {...} }
//
// Never throws — caller switches on `ok` and renders.

import { getOrCreateInstallId } from "./install_id.mjs";

const VERIFY_URL = process.env.DECOY_API_BASE
  ? `${process.env.DECOY_API_BASE.replace(/\/+$/, "")}/api/verify`
  : "https://app.decoy.run/api/verify";

const TIMEOUT_MS = 90_000; // matches worker LLM timeout budget

export async function verifyFindings({ results, token } = {}) {
  let installId;
  try { installId = getOrCreateInstallId(); }
  catch { return { ok: false, status: 0, code: "install_id_error", message: "Could not read or create ~/.decoy/install_id" }; }

  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res;
  try {
    res = await fetch(VERIFY_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ installId, results }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (e) {
    return { ok: false, status: 0, code: "network", message: e.message };
  }

  let body;
  try { body = await res.json(); } catch { body = {}; }

  if (res.status === 402) {
    return {
      ok: false,
      status: 402,
      code: "quota_exhausted",
      message: body.error || "Free verify quota exhausted",
      upgradeUrl: body.upgrade,
      quota: body.quota,
    };
  }
  if (res.status === 429) {
    return {
      ok: false,
      status: 429,
      code: "rate_limited",
      message: body.error || "Rate limited",
    };
  }
  if (!res.ok) {
    return {
      ok: false,
      status: res.status,
      code: "server_error",
      message: body.error || `Verify failed: HTTP ${res.status}`,
    };
  }

  return {
    ok: true,
    verified: body.verified || [],
    stats: body.stats || { input: 0, kept: 0, dropped: 0, escalated: 0 },
    quota: body.quota || null,
  };
}
