// Tests for install_id + telemetry helpers.
// Run: node --test test/telemetry.test.mjs

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

let tempHome;
let originalHome;
let originalUserProfile;
let originalTelemetryEnv;
let originalApiBaseEnv;

before(() => {
  originalHome = process.env.HOME;
  originalUserProfile = process.env.USERPROFILE;
  originalTelemetryEnv = process.env.DECOY_TELEMETRY;
  originalApiBaseEnv = process.env.DECOY_API_BASE;
});

beforeEach(() => {
  if (tempHome && existsSync(tempHome)) rmSync(tempHome, { recursive: true, force: true });
  tempHome = mkdtempSync(join(tmpdir(), "decoy-test-"));
  // os.homedir() on POSIX reads HOME; on Windows it reads USERPROFILE.
  // Set both so the test isolates the home directory across platforms.
  process.env.HOME = tempHome;
  process.env.USERPROFILE = tempHome;
  delete process.env.DECOY_TELEMETRY;
  delete process.env.DECOY_API_BASE;
});

after(() => {
  if (tempHome && existsSync(tempHome)) rmSync(tempHome, { recursive: true, force: true });
  process.env.HOME = originalHome;
  if (originalUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = originalUserProfile;
  if (originalTelemetryEnv === undefined) delete process.env.DECOY_TELEMETRY;
  else process.env.DECOY_TELEMETRY = originalTelemetryEnv;
  if (originalApiBaseEnv === undefined) delete process.env.DECOY_API_BASE;
  else process.env.DECOY_API_BASE = originalApiBaseEnv;
});

describe("install_id", () => {
  it("creates a valid UUID v4 on first call and persists it", async () => {
    const { getOrCreateInstallId } = await import("../lib/install_id.mjs?install1=" + Date.now());
    const id = getOrCreateInstallId();
    assert.match(id, UUID_RE);
    assert.ok(existsSync(join(tempHome, ".decoy", "install_id")));
    assert.equal(readFileSync(join(tempHome, ".decoy", "install_id"), "utf8").trim(), id);
  });

  it("returns the same UUID on subsequent calls", async () => {
    const { getOrCreateInstallId } = await import("../lib/install_id.mjs?install2=" + Date.now());
    const id1 = getOrCreateInstallId();
    const id2 = getOrCreateInstallId();
    assert.equal(id1, id2);
  });

  it("regenerates if the file contains garbage", async () => {
    const { getOrCreateInstallId, decoyDir } = await import("../lib/install_id.mjs?install3=" + Date.now());
    const dir = decoyDir();
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "install_id"), "not-a-uuid\n");
    const id = getOrCreateInstallId();
    assert.match(id, UUID_RE);
  });
});

describe("telemetry.telemetryDisabled", () => {
  it("returns false by default", async () => {
    const { telemetryDisabled } = await import("../lib/telemetry.mjs?td1=" + Date.now());
    assert.equal(telemetryDisabled(), false);
  });

  it("returns true when DECOY_TELEMETRY=0", async () => {
    process.env.DECOY_TELEMETRY = "0";
    const { telemetryDisabled } = await import("../lib/telemetry.mjs?td2=" + Date.now());
    assert.equal(telemetryDisabled(), true);
  });

  it("returns true when DECOY_TELEMETRY=false / off / no", async () => {
    const { telemetryDisabled } = await import("../lib/telemetry.mjs?td3=" + Date.now());
    process.env.DECOY_TELEMETRY = "false";
    assert.equal(telemetryDisabled(), true);
    process.env.DECOY_TELEMETRY = "off";
    assert.equal(telemetryDisabled(), true);
    process.env.DECOY_TELEMETRY = "NO";
    assert.equal(telemetryDisabled(), true);
  });

  it("returns true when --no-telemetry flag is passed (disabled: true)", async () => {
    const { telemetryDisabled } = await import("../lib/telemetry.mjs?td4=" + Date.now());
    assert.equal(telemetryDisabled({ flag: true }), true);
  });
});

describe("telemetry.sendEvent (v2)", () => {
  let originalFetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });

  it("no-ops with sent:false when disabled via env", async () => {
    process.env.DECOY_TELEMETRY = "0";
    let called = false;
    globalThis.fetch = async () => { called = true; return new Response("{}", { status: 200 }); };
    const { sendEvent } = await import("../lib/telemetry.mjs?send1=" + Date.now());
    const r = await sendEvent({ tool: "decoy-scan", version: "0.0.0", event: "scan.complete", payload: {} });
    assert.equal(r.sent, false);
    assert.equal(r.reason, "disabled");
    assert.equal(called, false);
    globalThis.fetch = originalFetch;
  });

  it("no-ops with sent:false when disabled via flag", async () => {
    let called = false;
    globalThis.fetch = async () => { called = true; return new Response("{}", { status: 200 }); };
    const { sendEvent } = await import("../lib/telemetry.mjs?send2=" + Date.now());
    const r = await sendEvent({ tool: "decoy-scan", version: "0.0.0", event: "scan.complete", payload: {}, disabled: true });
    assert.equal(r.sent, false);
    assert.equal(called, false);
    globalThis.fetch = originalFetch;
  });

  it("posts a v2 envelope with all required fields", async () => {
    process.env.DECOY_API_BASE = "https://test.decoy.local";
    let captured;
    globalThis.fetch = async (url, opts) => {
      captured = { url, opts };
      return new Response("{\"ok\":true}", { status: 200 });
    };
    const { sendEvent } = await import("../lib/telemetry.mjs?send3=" + Date.now());
    const r = await sendEvent({ tool: "decoy-scan", version: "1.2.3", event: "scan.complete", payload: { x: 1 } });
    assert.equal(r.sent, true);
    assert.equal(captured.url, "https://test.decoy.local/api/telemetry");
    const body = JSON.parse(captured.opts.body);
    assert.equal(body.schema_version, 2);
    assert.equal(body.tool, "decoy-scan");
    assert.equal(body.version, "1.2.3");
    assert.equal(body.event, "scan.complete");
    assert.match(body.installId, UUID_RE);
    assert.match(body.event_id, UUID_RE);
    assert.match(body.run_id, UUID_RE);
    assert.ok(body.ts);
    assert.ok(body.env);
    assert.ok(body.env.node);
    assert.ok(body.env.platform);
    globalThis.fetch = originalFetch;
  });

  it("queues to disk on network failure, returns sent:false reason:queued", async () => {
    globalThis.fetch = async () => { throw new Error("ECONNREFUSED"); };
    const { sendEvent } = await import("../lib/telemetry.mjs?send4=" + Date.now());
    const r = await sendEvent({ tool: "decoy-scan", version: "0.0.0", event: "scan.complete", payload: {} });
    assert.equal(r.sent, false);
    assert.equal(r.reason, "queued");
    // Event should be on disk in the queue file
    const queueFile = join(tempHome, ".decoy", "telemetry-queue.jsonl");
    assert.ok(existsSync(queueFile));
    const lines = readFileSync(queueFile, "utf8").trim().split("\n").filter(Boolean);
    assert.equal(lines.length, 1);
    const evt = JSON.parse(lines[0]);
    assert.equal(evt.schema_version, 2);
    assert.equal(evt.event, "scan.complete");
    globalThis.fetch = originalFetch;
  });

  it("drains queue on flushQueue", async () => {
    // Pre-populate queue
    globalThis.fetch = async () => { throw new Error("ECONNREFUSED"); };
    const { sendEvent, flushQueue } = await import("../lib/telemetry.mjs?flush1=" + Date.now());
    await sendEvent({ tool: "decoy-scan", version: "0.0.0", event: "scan.complete", payload: {} });
    await sendEvent({ tool: "decoy-scan", version: "0.0.0", event: "scan.discovery", payload: {} });
    // Now succeed
    let calls = 0;
    globalThis.fetch = async () => { calls++; return new Response("{\"ok\":true,\"accepted\":2,\"stored\":2}", { status: 200 }); };
    const drained = await flushQueue();
    assert.equal(drained, 2);
    assert.equal(calls, 1, "should batch into one POST");
    // Queue should be empty after drain
    const queueFile = join(tempHome, ".decoy", "telemetry-queue.jsonl");
    if (existsSync(queueFile)) {
      assert.equal(readFileSync(queueFile, "utf8").trim(), "");
    }
    globalThis.fetch = originalFetch;
  });

  it("legacy send() maps v1 event names to v2", async () => {
    let captured;
    globalThis.fetch = async (url, opts) => { captured = JSON.parse(opts.body); return new Response("{\"ok\":true}", { status: 200 }); };
    const { send } = await import("../lib/telemetry.mjs?legacy=" + Date.now());
    await send({ tool: "decoy-scan", version: "0.0.0", event: "scan_complete", payload: {} });
    assert.equal(captured.event, "scan.complete");
    assert.equal(captured.schema_version, 2);
    globalThis.fetch = originalFetch;
  });

  it("env detection: node version, platform, ci flag set correctly", async () => {
    let captured;
    globalThis.fetch = async (url, opts) => { captured = JSON.parse(opts.body); return new Response("{\"ok\":true}", { status: 200 }); };
    const { sendEvent } = await import("../lib/telemetry.mjs?env=" + Date.now());
    await sendEvent({ tool: "decoy-scan", version: "0.0.0", event: "scan.complete", payload: {} });
    assert.equal(captured.env.node, process.version);
    assert.equal(captured.env.platform, process.platform);
    assert.equal(typeof captured.env.ci, "boolean");
    globalThis.fetch = originalFetch;
  });

  it("inferHostFromConfigs picks the most-frequent host", async () => {
    const { inferHostFromConfigs } = await import("../lib/telemetry.mjs?host=" + Date.now());
    const configs = [
      { host: "Claude Desktop", servers: { a: {}, b: {} } },
      { host: "Cursor", servers: { c: {} } },
    ];
    assert.equal(inferHostFromConfigs(configs), "claude-desktop");
  });
});
