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
let originalTelemetryEnv;
let originalApiBaseEnv;

before(() => {
  originalHome = process.env.HOME;
  originalTelemetryEnv = process.env.DECOY_TELEMETRY;
  originalApiBaseEnv = process.env.DECOY_API_BASE;
});

beforeEach(() => {
  if (tempHome && existsSync(tempHome)) rmSync(tempHome, { recursive: true, force: true });
  tempHome = mkdtempSync(join(tmpdir(), "decoy-test-"));
  process.env.HOME = tempHome;
  delete process.env.DECOY_TELEMETRY;
  delete process.env.DECOY_API_BASE;
});

after(() => {
  if (tempHome && existsSync(tempHome)) rmSync(tempHome, { recursive: true, force: true });
  process.env.HOME = originalHome;
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

describe("telemetry.send", () => {
  let originalFetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });

  it("no-ops with sent:false when disabled via env", async () => {
    process.env.DECOY_TELEMETRY = "0";
    let called = false;
    globalThis.fetch = async () => { called = true; return new Response("{}", { status: 200 }); };
    const { send } = await import("../lib/telemetry.mjs?send1=" + Date.now());
    const r = await send({ tool: "decoy-scan", version: "0.0.0", event: "scan_complete", payload: {} });
    assert.equal(r.sent, false);
    assert.equal(r.reason, "disabled");
    assert.equal(called, false);
    globalThis.fetch = originalFetch;
  });

  it("no-ops with sent:false when disabled via flag", async () => {
    let called = false;
    globalThis.fetch = async () => { called = true; return new Response("{}", { status: 200 }); };
    const { send } = await import("../lib/telemetry.mjs?send2=" + Date.now());
    const r = await send({ tool: "decoy-scan", version: "0.0.0", event: "scan_complete", payload: {}, disabled: true });
    assert.equal(r.sent, false);
    assert.equal(called, false);
    globalThis.fetch = originalFetch;
  });

  it("posts to the configured URL with the right envelope", async () => {
    process.env.DECOY_API_BASE = "https://test.decoy.local";
    let captured;
    globalThis.fetch = async (url, opts) => {
      captured = { url, opts };
      return new Response("{\"ok\":true}", { status: 200 });
    };
    const { send } = await import("../lib/telemetry.mjs?send3=" + Date.now());
    const r = await send({ tool: "decoy-scan", version: "1.2.3", event: "scan_complete", payload: { x: 1 } });
    assert.equal(r.sent, true);
    assert.equal(r.status, 200);
    assert.equal(captured.url, "https://test.decoy.local/api/telemetry");
    const body = JSON.parse(captured.opts.body);
    assert.equal(body.tool, "decoy-scan");
    assert.equal(body.version, "1.2.3");
    assert.equal(body.event, "scan_complete");
    assert.match(body.installId, UUID_RE);
    globalThis.fetch = originalFetch;
  });

  it("returns sent:false on network error, never throws", async () => {
    globalThis.fetch = async () => { throw new Error("ECONNREFUSED"); };
    const { send } = await import("../lib/telemetry.mjs?send4=" + Date.now());
    const r = await send({ tool: "decoy-scan", version: "0.0.0", event: "scan_complete", payload: {} });
    assert.equal(r.sent, false);
    assert.equal(r.reason, "network");
    globalThis.fetch = originalFetch;
  });
});
