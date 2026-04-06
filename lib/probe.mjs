// Server probing — spawns MCP servers and extracts tools via JSON-RPC 2.0.

import { spawn } from "node:child_process";
import { PROBE_TIMEOUT_MS, STDERR_BUFFER_MAX, STDERR_HINT_MAX, MCP_PROTOCOL_VERSION, MCP_CLIENT_VERSION } from "./constants.mjs";

// Only forward env vars that servers legitimately need. Everything else stays out.
const SAFE_ENV_KEYS = ["PATH", "HOME", "NODE_PATH", "TERM", "LANG", "SHELL", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP"];

// Dangerous env vars that could enable code injection — strip from config-supplied env
const DANGEROUS_ENV_KEYS = ["LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP", "RUBYOPT", "PERL5OPT", "BASH_ENV", "ENV"];

export function probeServer(name, entry, env = {}) {
  return new Promise((resolve) => {
    const cmd = entry.command;
    const args = entry.args || [];
    const baseEnv = Object.fromEntries(SAFE_ENV_KEYS.filter(k => process.env[k]).map(k => [k, process.env[k]]));
    const configEnv = { ...env, ...(entry.env || {}) };
    for (const k of DANGEROUS_ENV_KEYS) delete configEnv[k];
    // Protect critical env vars from config override (e.g., PATH hijacking)
    for (const k of ["PATH", "HOME"]) { if (baseEnv[k]) delete configEnv[k]; }
    const serverEnv = { ...baseEnv, ...configEnv };

    let proc;
    try {
      proc = spawn(cmd, args, {
        env: serverEnv,
        stdio: ["pipe", "pipe", "pipe"],
        timeout: PROBE_TIMEOUT_MS,
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

    const timer = setTimeout(() => {
      finish({ name, error: `Timeout (${PROBE_TIMEOUT_MS / 1000}s)`, tools: [] });
    }, PROBE_TIMEOUT_MS);

    proc.stderr?.on("data", (chunk) => {
      stderrBuf += chunk.toString();
      if (stderrBuf.length > STDERR_BUFFER_MAX) stderrBuf = stderrBuf.slice(-STDERR_BUFFER_MAX);
    });

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();

      // Parse complete JSON lines from the buffer
      let newlineIdx;
      while ((newlineIdx = stdout.indexOf("\n")) !== -1) {
        const line = stdout.slice(0, newlineIdx).trim();
        stdout = stdout.slice(newlineIdx + 1);

        if (!line) continue;

        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          // Not valid JSON — could be partial write or non-JSON output. Skip it.
          continue;
        }

        // Validate it looks like a JSON-RPC message
        if (!msg || typeof msg !== "object") continue;

        // Wait for initialize response, then send tools/list
        if (!initDone && msg.id === 1 && msg.result) {
          initDone = true;
          const notif = JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
          const list = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
          try {
            proc.stdin.write(notif + "\n");
            proc.stdin.write(list + "\n");
          } catch {
            finish({ name, error: "Failed to send tools/list — stdin closed", tools: [] });
          }
          continue;
        }

        // Handle JSON-RPC error on initialize
        if (msg.id === 1 && msg.error) {
          clearTimeout(timer);
          const errMsg = msg.error.message || JSON.stringify(msg.error);
          finish({ name, error: `Initialize failed: ${errMsg}`, tools: [] });
          return;
        }

        // Got tools/list response
        if (msg.id === 2 && msg.result?.tools) {
          clearTimeout(timer);
          finish({ name, tools: msg.result.tools, error: null });
          return;
        }

        // Handle JSON-RPC error on tools/list
        if (msg.id === 2 && msg.error) {
          clearTimeout(timer);
          const errMsg = msg.error.message || JSON.stringify(msg.error);
          finish({ name, error: `tools/list failed: ${errMsg}`, tools: [] });
          return;
        }
      }
    });

    proc.on("error", (e) => {
      clearTimeout(timer);
      finish({ name, error: e.message, tools: [] });
    });

    proc.on("exit", (code) => {
      clearTimeout(timer);
      if (!resolved) {
        const hint = stderrBuf.trim().split("\n").pop()?.slice(0, STDERR_HINT_MAX) || "";
        const msg = hint ? `Exited with code ${code}: ${hint}` : `Exited with code ${code}`;
        finish({ name, error: msg, tools: [] });
      }
    });

    // Send MCP initialize
    const init = JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "decoy-scan", version: MCP_CLIENT_VERSION } },
    });

    try {
      proc.stdin.write(init + "\n");
    } catch {
      clearTimeout(timer);
      finish({ name, error: "Failed to write to stdin", tools: [] });
    }
  });
}
