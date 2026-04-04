// Advisory check — fetches vulnerability advisories from the Decoy API.

const ADVISORY_API = "https://app.decoy.run/monitor/mcp";

export async function checkAdvisories() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(ADVISORY_API, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) return { threats: [], error: null };
    return await res.json();
  } catch (e) {
    clearTimeout(timeout);
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
