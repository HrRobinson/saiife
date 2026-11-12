import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ACTIONS, outcome } from "../js/actions.js";
import { memoryStore } from "../js/keystore.js";

// The names in level.rs `REMOTE`, resolved through the `actions` consts.
function remoteNames() {
  const src = readFileSync(new URL("../../../wire/src/level.rs", import.meta.url), "utf8");
  const consts = new Map();
  for (const m of src.matchAll(/pub const ([A-Z_]+): &str = "([a-z0-9._]+)";/g)) {
    consts.set(m[1], m[2]);
  }
  const start = src.indexOf("pub const REMOTE");
  const block = src.slice(start, src.indexOf("];", start));
  const names = [];
  for (const m of block.matchAll(/\(a::([A-Z_]+), Level::/g)) {
    assert.ok(consts.has(m[1]), m[1]);
    names.push(consts.get(m[1]));
  }
  assert.ok(names.length > 10);
  return names;
}

test("every action name is in the Rust table", () => {
  const remote = remoteNames();
  for (const [k, v] of Object.entries(ACTIONS)) {
    assert.ok(remote.includes(v), `${k}: ${v} is not in REMOTE`);
  }
  assert.ok(Object.isFrozen(ACTIONS));
});

test("actions maps touch_required to needs_touch", () => {
  const no = (rule, error = rule) => ({ ok: false, error, rule, message: "m" });
  assert.equal(outcome(no("touch_required")), "needs_touch");
  assert.equal(outcome(no("unknown_device")), "unpaired");
  assert.equal(outcome(no("device_pending")), "pending");
  assert.equal(outcome(no("busy")), "retry");
  assert.equal(outcome(no(null, "unreachable")), "retry");
  assert.equal(outcome(no("expired")), "refused");
  assert.equal(outcome(no("invalid")), "refused");
  assert.equal(outcome(no("stale_epoch")), "refused");
  assert.equal(outcome(no(null, "bad_origin")), "refused");
  assert.equal(outcome({ ok: true, result: {} }), "done");
  assert.equal(outcome(undefined), "refused");
  assert.equal(outcome({ ok: "true" }), "refused");
  // A touch_required answer never reads as done, whatever else it carries.
  assert.equal(outcome({ ok: false, rule: "touch_required", result: {} }), "needs_touch");
});

test("memory store keeps one device record", async () => {
  const s = memoryStore();
  assert.equal(await s.loadDevice(), null);
  const rec = { key: {}, publicRaw: new Uint8Array(65), deviceId: "d-0011223344556677", machineId: "m" };
  await s.saveDevice(rec);
  assert.deepEqual(await s.loadDevice(), rec);
  await s.forgetDevice();
  assert.equal(await s.loadDevice(), null);
});

test("idb loadDevice is null without IndexedDB", async () => {
  const { loadDevice } = await import("../js/keystore.js");
  assert.equal(typeof globalThis.indexedDB, "undefined");
  assert.equal(await loadDevice(), null);
});
