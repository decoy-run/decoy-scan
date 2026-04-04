// Host config discovery — finds MCP server configurations across IDEs and tools.

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, platform } from "node:os";

const HOST_CONFIGS = {
  "Claude Desktop": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
    return join(homedir(), ".config", "claude", "claude_desktop_config.json");
  },
  "Cursor": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
    return join(homedir(), ".config", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
  },
  "Windsurf": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
    return join(homedir(), ".config", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
  },
  "VS Code": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Code", "User", "settings.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Code", "User", "settings.json");
    return join(homedir(), ".config", "Code", "User", "settings.json");
  },
  "Claude Code": () => join(homedir(), ".claude.json"),
  "Claude Code (project)": () => join(process.cwd(), ".mcp.json"),
  "Zed": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Zed", "settings.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Zed", "settings.json");
    return join(homedir(), ".config", "zed", "settings.json");
  },
  "Cline": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
    return join(homedir(), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
  },
};

export function discoverConfigs() {
  if (!homedir()) return [];
  const found = [];
  for (const [host, pathFn] of Object.entries(HOST_CONFIGS)) {
    const configPath = pathFn();
    if (existsSync(configPath)) {
      try {
        const raw = readFileSync(configPath, "utf8");
        const config = JSON.parse(raw);
        let servers = config.mcpServers || config["mcp.servers"] || {};
        if (host === "Zed" && config.context_servers) {
          servers = { ...servers, ...config.context_servers };
        }
        if (typeof servers !== "object") continue;
        found.push({ host, configPath, servers });
      } catch {
        // Skip malformed configs
      }
    }
  }
  return found;
}
