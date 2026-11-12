import test from "node:test";
import assert from "node:assert/strict";
import { headerLine, preview, hrefFor, reorderIds, counter, machineCommand, MAX_STEER_BYTES, doneText, stateClass, showsRuntime } from "../js/overviewlogic.js";

const b = (id, state) => ({ id, state });
const ov = {
  boxes: [b("r", "running"), b("d", "done"), b("q1", "queued"), b("q2", "queued")],
  load: { cpu_pct: 37, mem_used_mb: 6144, mem_total_mb: 16384 },
  slots_total: 4,
  slots_free: 3,
};

test("header line, with and without load", () => {
  assert.equal(headerLine(ov), "1 running · 2 queued · 3 free slots · CPU 37% · RAM 6.0/16.0 GB");
  assert.equal(headerLine({ ...ov, load: null }), "1 running · 2 queued · 3 free slots");
});

test("task preview cuts at 140 characters", () => {
  assert.deepEqual(preview("abc"), { text: "abc", cut: false });
  const p = preview("x".repeat(141));
  assert.equal(p.text.length, 140);
  assert.equal(p.cut, true);
});

test("cards link by state", () => {
  assert.equal(hrefFor(b("d", "done")), "#/box/d");
  assert.equal(hrefFor(b("r", "running")), "#/box/r/steer");
  assert.equal(hrefFor(b("p", "paused")), "#/box/p/steer");
  assert.equal(hrefFor(b("q", "queued")), null);
  assert.equal(hrefFor(b("l", "landed")), null);
});

test("reorder sends the full new order of queued boxes", () => {
  assert.deepEqual(reorderIds(ov.boxes, "q2", -1), ["q2", "q1"]);
  assert.deepEqual(reorderIds(ov.boxes, "q1", 1), ["q2", "q1"]);
  assert.equal(reorderIds(ov.boxes, "q1", -1), null);
  assert.equal(reorderIds(ov.boxes, "q2", 1), null);
  assert.equal(reorderIds(ov.boxes, "r", 1), null);
});

test("an action says what it did", () => {
  assert.equal(doneText("lockdown.on"), "Lockdown is on. Every agent is stopped.");
  assert.ok(doneText("box.reorder").length > 0);
  assert.ok(doneText("box.anything").length > 0);
});

test("badge class only from the known states", () => {
  assert.equal(stateClass("running"), "state-running");
  assert.equal(stateClass("discarded"), "state-discarded");
  assert.equal(stateClass("x onerror"), "state-other");
  assert.equal(stateClass("constructor"), "state-other");
  assert.equal(stateClass(undefined), "state-other");
});

test("running for only on running and paused boxes", () => {
  assert.equal(showsRuntime({ state: "running", started_at: 5 }), true);
  assert.equal(showsRuntime({ state: "paused", started_at: 5 }), true);
  for (const state of ["done", "landed", "discarded", "queued", "starting"]) {
    assert.equal(showsRuntime({ state, started_at: 5 }), false, state);
  }
  assert.equal(showsRuntime({ state: "running", started_at: null }), false);
});

test("steer counter counts bytes", () => {
  assert.deepEqual(counter("é"), { text: `2 / ${MAX_STEER_BYTES} bytes`, over: false });
  assert.equal(counter("a".repeat(4097)).over, true);
  assert.equal(counter("a".repeat(4096)).over, false);
});

test("machine commands", () => {
  assert.equal(machineCommand("box.land", "b-1"), "saiife box land b-1");
  assert.equal(machineCommand("box.steer", "b-1"), 'saiife box say b-1 "…"');
});

class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener() {}
  append(...k) { this.children.push(...k); }
}
globalThis.document = { createElement: (t) => new Node_(t), createTextNode: (s) => ({ text: s }) };
const texts = (n) => (n.text !== undefined ? [n.text] : n.children.flatMap(texts));

test("touch prompt shows the ask, the box, the code and the command, never success", async () => {
  const { show } = await import("../js/touchprompt.js");
  const all = texts(show({ short_code: "ABC123", message: "needs a touch" }, { action: "box.land", id: "b-1", summary: "Land b-1" })).join("|");
  for (const s of ["Land b-1", "b-1", "ABC123", "Needs a touch on a paired passkey", "saiife box land b-1"]) {
    assert.ok(all.includes(s), s);
  }
  assert.ok(!/sent|paused|stopped|done\b/i.test(all.replace("Not done yet", "")));
  const none = texts(show({}, { action: "box.steer", id: "b-2" })).join("|");
  assert.ok(!none.includes("Code:"));
});

test("no invented machine commands", () => {
  assert.equal(machineCommand("box.spawn", ""), null);
  assert.equal(machineCommand("class:push_protected", "b-1"), null);
  assert.equal(machineCommand("box.land", "b-1"), "saiife box land b-1");
});

test("prompt for spawn and push_protected has no command and no empty Box line", async () => {
  const { show } = await import("../js/touchprompt.js");
  for (const [action, id] of [["box.spawn", ""], ["class:push_protected", "b-1"]]) {
    const all = texts(show({ short_code: "123456" }, { action, id, summary: "x" })).join("|");
    assert.ok(!all.includes("saiife box"), all);
    assert.ok(!all.includes("On the machine, run:"), all);
    assert.ok(all.includes("Approve it on the machine."), all);
    assert.ok(id ? all.includes("Box: b-1") : !all.includes("Box:"), all);
  }
  const land = texts(show({}, { action: "box.land", id: "b-1" })).join("|");
  assert.ok(land.includes("saiife box land b-1"));
});
