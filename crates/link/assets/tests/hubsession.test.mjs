// hubsession.js over the in-memory relay and machine (no network).
import { test } from "node:test";
import assert from "node:assert/strict";
import { HubSession, HubError, hubFetch, CLOSE } from "../js/hubsession.js";
import { Client, b64u, unb64u, deviceIdOf } from "../js/wire.js";
import { memoryStore } from "../js/keystore.js";
import { fakeMachine } from "./fakes/fakemachine.mjs";
import { fakeRelay } from "./fakes/fakerelay.mjs";

const P256 = { name: "ECDSA", namedCurve: "P-256" };
const dec = new TextDecoder();

async function newDevice() {
  const pair = await crypto.subtle.generateKey(P256, false, ["sign", "verify"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { key: pair.privateKey, publicRaw, deviceId: await deviceIdOf(publicRaw), machineId: "0123456789abcdef0123456789abcdef" };
}

// A machine that knows one device, a relay in front, and a session factory.
async function world({ answers } = {}) {
  const dev = await newDevice();
  const machine = await fakeMachine({
    devices: new Map([[dev.deviceId, dev.publicRaw]]),
    answers:
      answers ??
      (async (p) =>
        p.t === "hello"
          ? { ok: true, result: { machine_id: dev.machineId, machine_pub: b64u(machine.machinePub), epoch: "e1", frame_version: 1 } }
          : { ok: true, result: { echo: p.t } }),
  });
  const relay = fakeRelay({ machine });
  let tickets = 0;
  const make = (extra = {}) =>
    new HubSession({
      getTicket: async () => {
        tickets++;
        return relay.tickets.issue();
      },
      machinePub: machine.machinePub,
      binding: { deviceId: dev.deviceId },
      deviceKey: dev.key,
      WebSocket: relay.WebSocket,
      ...extra,
    });
  return { dev, machine, relay, make, count: () => tickets };
}

const texts = (relay) => relay.sent.filter((x) => typeof x === "string").map((x) => JSON.parse(x));
const innerOf = (m) => JSON.parse(dec.decode(unb64u(m.data)));

test("CLOSE map is the contract", () => {
  assert.equal(CLOSE[4402], "pro_required");
  assert.equal(CLOSE[4413], "too_big");
  assert.equal(CLOSE[4429], "busy");
  assert.equal(CLOSE[1011], "internal_error");
  assert.ok(Object.isFrozen(CLOSE));
});

test("opens a device session and answers hello", async () => {
  const w = await world();
  const s = w.make();
  await s.open();
  const a = await s.call({ t: "hello" });
  assert.equal(a.t, "result");
  assert.equal(a.ok, true);
  assert.equal(a.result.epoch, "e1");
  const sent = texts(w.relay);
  assert.deepEqual(sent[0], { t: "connect", v: 1, ticket: sent[0].ticket });
  assert.deepEqual(Object.keys(innerOf(sent[1])).sort(), ["browser_eph", "device_id", "t"]);
  assert.deepEqual(Object.keys(innerOf(sent[2])).sort(), ["sig", "t"]);
  // compact JSON, text only
  for (const x of w.relay.sent) assert.equal(typeof x, "string");
  assert.equal(w.relay.sent[1], JSON.stringify(JSON.parse(w.relay.sent[1])));
  s.close();
});

test("refuses a machine_sig made for another binding", async () => {
  const w = await world();
  w.machine.faults.sigFor = { deviceId: "d-0000000000000000" };
  const s = w.make();
  await assert.rejects(s.open(), (e) => e instanceof HubError && e.code === "bad_answer" && e.stage === "handshake");
});

test("refuses a seal_hello with an extra key", async () => {
  const w = await world();
  w.machine.faults.extraKey = true;
  const s = w.make();
  await assert.rejects(s.open(), (e) => e.code === "bad_answer");
});

test("nothing but seal_hello is sent before the machine signature verifies", async () => {
  const w = await world();
  w.machine.faults.badSig = true;
  const closed = [];
  const s = w.make();
  s.onclose = (e) => closed.push(e);
  await assert.rejects(s.open());
  const sent = texts(w.relay);
  assert.equal(sent.length, 2);
  assert.equal(sent[0].t, "connect");
  assert.equal(innerOf(sent[1]).t, "seal_hello");
  assert.equal(closed.length, 1);
  assert.equal(closed[0].code, "bad_answer");
});

test("calls are answered in order", async () => {
  const seen = [];
  const w = await world({
    answers: async (p) => {
      seen.push(p.t);
      return { ok: true, result: { n: seen.length } };
    },
  });
  const s = w.make();
  await s.open();
  const rs = await Promise.all([s.call({ t: "hello" }), s.call({ t: "frame", body: "b", sig: "s" }), s.call({ t: "hello" })]);
  assert.deepEqual(rs.map((r) => r.result.n), [1, 2, 3]);
  assert.deepEqual(seen, ["hello", "frame", "hello"]);
  s.close();
});

test("call timeout closes the session", async () => {
  const w = await world({ answers: () => new Promise(() => {}) });
  const timers = [];
  const fakeSet = (f, ms) => {
    timers.push({ f, ms, live: true });
    return timers.length - 1;
  };
  const fakeClear = (i) => {
    if (timers[i]) timers[i].live = false;
  };
  const s = w.make({ setTimeout: fakeSet, clearTimeout: fakeClear });
  const closed = [];
  s.onclose = (e) => closed.push(e);
  await s.open();
  const p = s.call({ t: "hello" });
  const q = s.call({ t: "hello" });
  await new Promise((r) => setTimeout(r, 20));
  const t = timers.filter((x) => x.live && x.ms === 30000);
  assert.equal(t.length, 1);
  t[0].f();
  await assert.rejects(p, (e) => e.code === "timeout");
  await assert.rejects(q, (e) => e instanceof HubError);
  assert.equal(closed.length, 1);
  assert.equal(closed[0].code, "timeout");
  await assert.rejects(s.call({ t: "hello" }), (e) => e instanceof HubError);
});

test("4402 surfaces pro_required and hubFetch answers 402", async () => {
  const w = await world();
  const s = new HubSession({
    getTicket: async () => w.relay.tickets.issue({ close: 4402 }),
    machinePub: w.machine.machinePub,
    binding: { deviceId: w.dev.deviceId },
    deviceKey: w.dev.key,
    WebSocket: w.relay.WebSocket,
  });
  await assert.rejects(s.open(), (e) => e.code === "pro_required" && e.stage === "connect");
  const f = hubFetch(async () => {
    throw new HubError("pro_required", "connect");
  });
  const r = await f("/api/hello", { method: "GET" });
  assert.equal(r.status, 402);
  assert.deepEqual(await r.json(), { error: "pro_required" });
});

test("reconnects after 4410 with a new ticket", async () => {
  const w = await world();
  const s1 = w.make();
  const closed = [];
  s1.onclose = (e) => closed.push(e);
  await s1.open();
  w.relay.closeAll(4410);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(closed.length, 1);
  assert.equal(closed[0].code, "machine_reconnected");
  await assert.rejects(s1.call({ t: "hello" }), (e) => e.code === "machine_reconnected");
  const s2 = w.make();
  await s2.open();
  assert.equal(w.count(), 2);
  assert.equal(w.relay.tickets.used.size, 2);
  assert.equal((await s2.call({ t: "hello" })).ok, true);
  s2.close();
});

test("a used ticket is refused by the relay (4401)", async () => {
  const w = await world();
  const t = w.relay.tickets.issue();
  const mk = () =>
    new HubSession({ getTicket: async () => t, machinePub: w.machine.machinePub, binding: { deviceId: w.dev.deviceId }, deviceKey: w.dev.key, WebSocket: w.relay.WebSocket });
  const a = mk();
  await a.open();
  a.close();
  await assert.rejects(mk().open(), (e) => e.code === "bad_ticket");
});

test("close codes name by number, never by reason", async () => {
  const w = await world();
  const s = w.make();
  await s.open();
  w.relay.closeAll(4413);
  await assert.rejects(s.call({ t: "hello" }), (e) => e.code === "too_big");
  const s2 = w.make();
  await s2.open();
  w.relay.closeAll(4999);
  await assert.rejects(s2.call({ t: "hello" }), (e) => e.code === "closed");
});

test("binary messages are ignored", async () => {
  const w = await world();
  const s = w.make();
  const ws = [];
  const Base = w.relay.WebSocket;
  class Spy extends Base {
    constructor(u) {
      super(u);
      ws.push(this);
    }
  }
  const s2 = w.make({ WebSocket: Spy });
  await s2.open();
  ws[0].dispatchEvent(Object.assign(new Event("message"), { data: new Uint8Array([1, 2, 3]).buffer }));
  assert.equal((await s2.call({ t: "hello" })).ok, true);
  s2.close();
  void s;
});

test("an unasked message closes with bad_answer", async () => {
  const w = await world();
  const ws = [];
  const Base = w.relay.WebSocket;
  class Spy extends Base {
    constructor(u) {
      super(u);
      ws.push(this);
    }
  }
  const s = w.make({ WebSocket: Spy });
  const closed = [];
  s.onclose = (e) => closed.push(e);
  await s.open();
  ws[0].dispatchEvent(Object.assign(new Event("message"), { data: JSON.stringify({ t: "msg", data: "AAAA" }) }));
  assert.equal(closed.length, 1);
  assert.equal(closed[0].code, "bad_answer");
});

test("the relay refuses the first device message unless it is a seal_hello", async () => {
  const w = await world();
  const ws = new w.relay.WebSocket("wss://relay.test/v1/device");
  const closes = [];
  ws.addEventListener("close", (e) => closes.push(e.code));
  const msgs = [];
  ws.addEventListener("message", (e) => msgs.push(e.data));
  await new Promise((r) => setTimeout(r, 5));
  const { ticket } = w.relay.tickets.issue();
  ws.send(JSON.stringify({ t: "connect", v: 1, ticket }));
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(JSON.parse(msgs[0]).t, "ready");
  ws.send(new Uint8Array([1]));
  await new Promise((r) => setTimeout(r, 5));
  assert.deepEqual(closes, [4400]);
});

test("the relay closes a socket that never sends connect (4408)", async () => {
  const w = await world();
  const relay = fakeRelay({ machine: w.machine, connectWindowMs: 20 });
  const ws = new relay.WebSocket("wss://relay.test/v1/device");
  const closes = [];
  ws.addEventListener("close", (e) => closes.push(e.code));
  await new Promise((r) => setTimeout(r, 60));
  assert.deepEqual(closes, [4408]);
});

test("a pending device is closed before seal_hello (4000)", async () => {
  const w = await world();
  w.machine.pending.add(w.dev.deviceId);
  await assert.rejects(w.make().open(), (e) => e.code === "closed_by_machine" && e.stage === "handshake");
});

test("a pairing binding opens without seal_auth", async () => {
  const w = await world();
  w.machine.offers.set("pair-1", { secret: "s" });
  const s = new HubSession({
    getTicket: async () => w.relay.tickets.issue(),
    machinePub: w.machine.machinePub,
    binding: { pairId: "pair-1" },
    WebSocket: w.relay.WebSocket,
  });
  await s.open();
  const sent = texts(w.relay);
  assert.equal(sent.length, 2);
  assert.deepEqual(Object.keys(innerOf(sent[1])).sort(), ["browser_eph", "pair_id", "t"]);
  s.close();
});

test("hubFetch maps /api/frame to a sealed frame and back", async () => {
  const w = await world({
    answers: async (p, b) => {
      if (p.t === "hello") {
        return { ok: true, result: { machine_id: w2.dev.machineId, machine_pub: "AA", epoch: "e1", frame_version: 1 } };
      }
      return { ok: true, result: { stopped: true, via: b.deviceId } };
    },
  });
  const w2 = w;
  const s = w.make();
  await s.open();
  const store = memoryStore();
  await store.saveDevice(w.dev);
  const c = new Client({ fetch: hubFetch(async () => s), store, now: () => 1700000000 });
  const a = await c.send("box.stop", { box: "b1" });
  assert.deepEqual(a, { ok: true, result: { stopped: true, via: w.dev.deviceId } });
  const frame = w.machine.seen.find((p) => p.t === "frame");
  assert.deepEqual(Object.keys(frame).sort(), ["body", "sig", "t"]);
  assert.equal(JSON.parse(frame.body).action, "box.stop");
  s.close();
});

test("hubFetch: unknown paths 404, a dead session rejects, a refusal passes through", async () => {
  const f = hubFetch(async () => {
    throw new HubError("closed_by_machine", "open");
  });
  assert.equal((await f("/api/other", {})).status, 404);
  assert.deepEqual(await (await f("/api/other", {})).json(), { error: "not_found" });
  await assert.rejects(f("/api/frame", { method: "POST", body: JSON.stringify({ body: "b", sig: "s" }) }), (e) => e.code === "closed_by_machine");
  const w = await world({ answers: async () => ({ ok: false, error: "refused", rule: "r", message: "no" }) });
  const s = w.make();
  await s.open();
  const g = hubFetch(async () => s);
  const ok = await g("/api/hello", { method: "GET" });
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), { ok: false, error: "refused", rule: "r", message: "no" });
  s.close();
});

test("a 4410 during a Client call says the Workspace link is not reachable; a fresh session works", async () => {
  let hang = true;
  const w = await world({
    answers: async (p) =>
      p.t === "hello"
        ? { ok: true, result: { machine_id: "0123456789abcdef0123456789abcdef", machine_pub: "AA", epoch: "e1", frame_version: 1 } }
        : hang
          ? new Promise(() => {})
          : { ok: true, result: { stopped: true } },
  });
  let cur = w.make();
  await cur.open();
  const store = memoryStore();
  await store.saveDevice(w.dev);
  const c = new Client({ fetch: hubFetch(async () => cur), store, now: () => 1700000000 });
  const p = c.send("box.stop", { box: "b1" });
  await new Promise((r) => setTimeout(r, 30));
  w.relay.closeAll(4410);
  const a = await p;
  assert.equal(a.ok, false);
  assert.equal(a.message, "The Workspace link is not reachable");
  hang = false;
  cur = w.make();
  await cur.open();
  assert.deepEqual(await c.send("box.stop", { box: "b1" }), { ok: true, result: { stopped: true } });
  cur.close();
});

test("open() rejects with timeout at the bound even if getTicket never settles", async () => {
  const w = await world();
  const timers = [];
  const s = w.make({
    getTicket: () => new Promise(() => {}),
    setTimeout: (f, ms) => (timers.push({ f, ms, live: true }), timers.length - 1),
    clearTimeout: (i) => {
      if (timers[i]) timers[i].live = false;
    },
  });
  const closed = [];
  s.onclose = (e) => closed.push(e);
  const p = s.open();
  await new Promise((r) => setTimeout(r, 5));
  timers.find((x) => x.live && x.ms === 15000).f();
  await assert.rejects(p, (e) => e instanceof HubError && e.code === "timeout");
  assert.equal(closed.length, 1);
});
