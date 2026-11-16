import test from "node:test";
import assert from "node:assert/strict";
import { h } from "../js/dom.js";
import { apply, render, poller, POLL_MS, ENDED } from "../js/term.js";

// A tiny fake document (as dom.test.mjs).
class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { this.listeners[t] = f; }
  append(...kids) { this.children.push(...kids); }
  replaceChildren(...kids) { this.children = kids; }
}
globalThis.document = {
  createElement: (t) => new Node_(t),
  createTextNode: (s) => ({ text: s }),
};

function tags(n, out = []) {
  if (n instanceof Node_) {
    out.push(n.tag);
    for (const c of n.children) tags(c, out);
  }
  return out;
}
function texts(n, out = []) {
  if (n instanceof Node_) for (const c of n.children) texts(c, out);
  else out.push(n.text);
  return out;
}

const snap = (seq, lines) => ({ snapshot: { seq, rows: lines.length, cols: 40, lines, cursor: [0, 0] } });
const delta = (seq, lines) => ({ delta: { seq, lines, cursor: [0, 0] } });

test("term apply snapshot and delta", () => {
  let r = apply(null, snap(1, ["$ cargo test", "running 41 tests"]));
  assert.equal(r.gap, false);
  assert.deepEqual(r.screen.lines, ["$ cargo test", "running 41 tests"]);
  assert.equal(r.screen.seq, 1);
  const before = r.screen;
  r = apply(r.screen, delta(2, [[1, "test result: ok"]]));
  assert.equal(r.gap, false);
  assert.deepEqual(r.screen.lines, ["$ cargo test", "test result: ok"]);
  assert.equal(r.screen.seq, 2);
  // The old screen is not changed in place.
  assert.deepEqual(before.lines, ["$ cargo test", "running 41 tests"]);
  // A row outside the screen is ignored.
  r = apply(r.screen, delta(3, [[9, "nowhere"]]));
  assert.deepEqual(r.screen.lines, ["$ cargo test", "test result: ok"]);
  // A new snapshot replaces everything.
  r = apply(r.screen, snap(7, ["fresh"]));
  assert.deepEqual(r.screen.lines, ["fresh"]);
  assert.equal(r.screen.seq, 7);
});

test("term seq gap asks for snapshot", async () => {
  // A delta that is not last + 1, or one before any snapshot, is a gap.
  const s = apply(null, snap(1, ["a"])).screen;
  const g = apply(s, delta(3, [[0, "b"]]));
  assert.equal(g.gap, true);
  assert.deepEqual(g.screen, s);
  assert.equal(apply(null, delta(1, [[0, "x"]])).gap, true);
  assert.equal(apply(s, { bogus: 1 }).gap, true);

  // The poller asks for a fresh snapshot (no `after`) after a gap.
  const answers = [
    { ok: true, result: { frames: [snap(1, ["a"])], next: 1, ended: false } },
    { ok: true, result: { frames: [delta(3, [[0, "b"]])], next: 3, ended: false } },
    { ok: true, result: { frames: [snap(3, ["b"])], next: 3, ended: false } },
  ];
  const sent = [];
  const client = { async send(action, args) { sent.push([action, args]); return answers.shift(); } };
  let t = 0;
  const p = poller({ client, id: "b-run", schedule: () => 1, cancel: () => {}, now: () => t, onUpdate: () => {} });
  p.start();
  await p.idle();
  t += POLL_MS;
  await p.tick();
  t += POLL_MS;
  await p.tick();
  assert.deepEqual(sent, [
    ["box.term.read", { id: "b-run" }],
    ["box.term.read", { id: "b-run", after: 1 }],
    ["box.term.read", { id: "b-run" }],
  ]);
  assert.deepEqual(p.screen.lines, ["b"]);
  p.stop();
});

test("term render is inert", () => {
  const screen = apply(null, snap(1, [
    "\u001b]52;c;cm0gLXJmIH4=\u0007",
    "\u001b]8;;https://x\u0007Approve\u001b]8;;\u0007",
    "evil‮gnp.exe",
    "[ Approve ] <button>Approve</button> <a href=x>y</a>",
    "two\nlines",
  ])).screen;
  const pre = render(screen, h);
  assert.equal(pre.tag, "pre");
  const t = tags(pre);
  for (const bad of ["a", "button", "input", "form", "textarea", "select"]) {
    assert.ok(!t.includes(bad), `no ${bad} in ${t}`);
  }
  assert.deepEqual(t, ["pre"]);
  const lines = texts(pre);
  assert.equal(lines.length, 5, "one text node per line");
  assert.equal(lines[0], "⟨ESC⟩]52;c;cm0gLXJmIH4=⟨U+0007⟩\n");
  assert.ok(lines[1].startsWith("⟨ESC⟩]8;;https://x⟨U+0007⟩Approve"));
  assert.equal(lines[2], "evil⟨U+202E⟩gnp.exe\n");
  assert.equal(lines[3], "[ Approve ] <button>Approve</button> <a href=x>y</a>\n");
  // A newline inside one line cannot draw a line of its own.
  assert.equal(lines[4], "two⟨U+000A⟩lines");
  assert.equal(render(null, h).tag, "pre");
});

test("term polls at most once per second", async () => {
  let calls = 0;
  const client = {
    async send() {
      calls++;
      return { ok: true, result: { frames: [], next: 0, ended: false } };
    },
  };
  let t = 0;
  const p = poller({ client, id: "b-run", schedule: () => 1, cancel: () => {}, now: () => t, onUpdate: () => {} });
  p.start();
  await p.idle();
  // Ten more ticks inside the same second: no further read.
  for (let i = 0; i < 10; i++) {
    t += 99;
    await p.tick();
  }
  assert.equal(calls, 1);
  t = POLL_MS;
  await p.tick();
  assert.equal(calls, 2);
  // Ticks while a read is in flight do not stack.
  let release;
  const slow = { async send() { calls++; await new Promise((r) => (release = r)); return { ok: true, result: { frames: [], next: 0, ended: false } }; } };
  calls = 0;
  t = 0;
  const q = poller({ client: slow, id: "b-run", schedule: () => 1, cancel: () => {}, now: () => t, onUpdate: () => {} });
  q.start();
  for (let i = 0; i < 5; i++) {
    t += POLL_MS;
    q.tick();
  }
  assert.equal(calls, 1);
  release();
  await q.idle();
  q.stop();
  p.stop();
});

test("term ended stops polling", async () => {
  let calls = 0;
  let cancelled = 0;
  const updates = [];
  const client = { async send() { calls++; return { ok: true, result: { frames: [snap(1, ["done"])], next: 1, ended: true } }; } };
  let t = 0;
  const p = poller({ client, id: "b-done", schedule: () => 7, cancel: (x) => { if (x === 7) cancelled++; }, now: () => t, onUpdate: (u) => updates.push(u) });
  p.start();
  await p.idle();
  t += 5 * POLL_MS;
  await p.tick();
  assert.equal(calls, 1);
  assert.equal(cancelled, 1);
  assert.equal(updates.at(-1).ended, true);
  assert.equal(ENDED, "The terminal has ended");
});
