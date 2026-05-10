// Anonymous telemetry client for decoy-* CLIs.
//
// Default: ON. Free runs phone home findings + run summaries to /api/telemetry
// using a stable installId (no email, no IP, no hostname). This is how we learn
// which patterns produce false positives in the wild — see project_data_collection_moat.
//
// Opt-out: DECOY_TELEMETRY=0 env var or `--no-telemetry` CLI flag (caller passes
// `disabled: true` to send()). Both routes silently no-op the network call.
//
// First-run notice: a single line printed once per machine, cached at
// ~/.decoy/telemetry-notice-shown. Not a modal. Not a blocker.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { decoyDir, getOrCreateInstallId } from "./install_id.mjs";

const TELEMETRY_URL = process.env.DECOY_API_BASE
  ? `${process.env.DECOY_API_BASE.replace(/\/+$/, "")}/api/telemetry`
  : "https://app.decoy.run/api/telemetry";

const TIMEOUT_MS = 2000;

export function telemetryDisabled({ flag = false } = {}) {
  if (flag) return true;
  const env = String(process.env.DECOY_TELEMETRY ?? "").toLowerCase();
  return env === "0" || env === "false" || env === "off" || env === "no";
}

export function maybePrintFirstRunNotice({ tool, stream = process.stderr } = {}) {
  if (telemetryDisabled()) return;
  const noticeFile = join(decoyDir(), "telemetry-notice-shown");
  if (existsSync(noticeFile)) return;
  try {
    if (!existsSync(decoyDir())) mkdirSync(decoyDir(), { recursive: true });
    writeFileSync(noticeFile, new Date().toISOString() + "\n", { mode: 0o600 });
  } catch {
    // If we can't persist the marker, we'll print again next time. Not fatal.
  }
  stream.write(
    `${tool} reports anonymized findings to improve detections. ` +
    `Disable: DECOY_TELEMETRY=0 or --no-telemetry. Details: https://decoy.run/privacy\n`,
  );
}

// Fire-and-await with a hard timeout. The CLI process is about to exit, so we
// can't truly fire-and-forget — we need the request to actually leave before
// node tears down. 2s is enough for normal latency, short enough not to annoy.
export async function send({ tool, version, event, payload, disabled = false } = {}) {
  if (telemetryDisabled({ flag: disabled })) return { sent: false, reason: "disabled" };
  let installId;
  try { installId = getOrCreateInstallId(); }
  catch { return { sent: false, reason: "install_id_error" }; }

  const body = JSON.stringify({ tool, version, installId, event, payload: payload ?? null });
  try {
    const res = await fetch(TELEMETRY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    return { sent: true, status: res.status, installId };
  } catch (e) {
    // Network error / timeout — silent. Telemetry never breaks the user's run.
    return { sent: false, reason: "network", error: e.message };
  }
}

export function readInstallId() {
  return getOrCreateInstallId();
}

// Compress a scan result down to the structural signal we want at the worker
// without shipping raw tool descriptions, full file paths, or anything else
// that could embed user data. Keep this conservative — when in doubt, drop the
// field. Easier to add fields later than apologize for ones we shipped.
export function summarizeScanForTelemetry(results) {
  if (!results) return null;
  return {
    timestamp: results.timestamp,
    summary: results.summary,
    owasp: results.owasp,
    serverCount: results.servers?.length ?? 0,
    servers: (results.servers || []).map(s => ({
      decoy: !!s.decoy,
      error: s.error ? true : false,
      toolCount: (s.tools || []).length,
      findingCount: (s.findings || []).length,
      findingSources: (s.findings || []).reduce((acc, f) => {
        acc[f.source] = (acc[f.source] || 0) + 1;
        return acc;
      }, {}),
      severities: (s.findings || []).reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {}),
      risk: s.risk,
    })),
    toxicFlowCount: (results.toxicFlows || []).length,
  };
}
