import test from "node:test";
import assert from "node:assert/strict";
import { poller } from "../js/poller.js";

// fn calls resolve in order through `gates`; each call waits for its gate.
function gated() {
  const gates = [];
  let calls = 0;
  const fn = () => {
    calls++;
    return new Promise((resolve, reject) => gates.push({ resolve, reject }));
  };
  return { fn, gates, calls: () => calls };
}
const settle = () => new Promise((r) => setImmediate(r));

test("a timer tick during a poll is skipped", async () => {
  const g = gated();
  const p = poller(g.fn);
  p.tick();
  p.tick();
  await settle();
  assert.equal(g.calls(), 1);
  g.gates[0].resolve();
  await settle();
  assert.equal(p.busy, false);
  assert.equal(g.calls(), 1);
});

test("a refresh after an action during a poll runs once more after it", async () => {
  const g = gated();
  const p = poller(g.fn);
  p.tick();
  p.now();
  p.now();
  await settle();
  assert.equal(g.calls(), 1, "never two at once");
  g.gates[0].resolve();
  await settle();
  assert.equal(g.calls(), 2, "the action's refresh runs");
  g.gates[1].resolve();
  await settle();
  assert.equal(g.calls(), 2);
  assert.equal(p.busy, false);
});

test("a failing poll never leaves the screen stuck", async () => {
  const g = gated();
  const p = poller(g.fn);
  p.tick();
  await settle();
  g.gates[0].reject(new Error("boom"));
  await settle();
  assert.equal(p.busy, false);
  p.tick();
  await settle();
  assert.equal(g.calls(), 2);
  const sync = poller(() => { throw new Error("sync"); });
  await sync.now();
  assert.equal(sync.busy, false);
});
