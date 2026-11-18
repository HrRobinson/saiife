// hubpair.js over the in-memory relay and machine (no network).
import { test } from "node:test";
import assert from "node:assert/strict";
import { pairOverHub, waitConfirmOverHub, HUB_POLL_MS, PRO_SENTENCE } from "../js/hubpair.js";
import { shortCode, CODES_DIFFER } from "../js/pairing.js";
import { b64u, unb64u, deviceIdOf } from "../js/wire.js";
import { fakeMachine } from "./fakes/fakemachine.mjs";
import { fakeRelay } from "./fakes/fakerelay.mjs";

const dec = new TextDecoder();
const NOT_MACHINE = "The machine did not prove it is the one in this pairing link";
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

// A machine with one open offer, a relay in front, and the offer the page
// parsed from the fragment.
async function world({ refusePasskey = false, wrongCode = false } = {}) {
  const pairId = b64u(crypto.getRandomValues(new Uint8Array(8)));
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const log = [];
  const machine = await fakeMachine({
    offers: new Map([[pairId, { secret }]]),
    answers: async (p, binding) => {
      if (p.t === "pair") {
        log.push(p);
        if (refusePasskey && p.passkey) {
          return { ok: false, error: "bad_request", rule: "passkey_refused", message: "no" };
        }
        const pub = unb64u(p.device_pub);
        const id = await deviceIdOf(pub);
        machine.pending.add(id);
        machine.devices.set(id, pub);
        const code = wrongCode ? "000 000" : await shortCode(machine.machinePub, pub, secret);
        return { ok: true, result: { device_id: id, short_code: code } };
      }
      if (p.t === "hello") {
        const id = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", machine.machinePub))).slice(0, 32);
        return { ok: true, result: { machine_id: id, machine_pub: b64u(machine.machinePub), epoch: "e1", frame_version: 1 } };
      }
      return { ok: true, result: { passkeys: [] } };
    },
  });
  const relay = fakeRelay({ machine });
  const machineId = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", machine.machinePub))).slice(0, 32);
  const offer = { pairId, secret, machineId, machinePub: machine.machinePub };
  let tickets = 0;
  const getTicket = async () => {
    tickets++;
    return relay.tickets.issue();
  };
  return { machine, relay, offer, getTicket, log, count: () => tickets };
}

function fakeCredentials(log) {
  const authData = Uint8Array.from({ length: 80 }, (_, i) => i + 1);
  const cdj = new TextEncoder().encode('{"type":"webauthn.create"}');
  return {
    async create(opts) {
      log.push(opts);
      return {
        rawId: Uint8Array.from([9, 8, 7, 6]).buffer,
        response: { getAuthenticatorData: () => authData.buffer, clientDataJSON: cdj.buffer },
      };
    },
  };
}

const none = { credentials: null, hasPublicKey: false, hostname: "workspace.saiife.com" };

test("pairs over the hub and returns the device in memory", async () => {
  const w = await world();
  const r = await pairOverHub({ offer: w.offer, label: "Laptop", getTicket: w.getTicket, WebSocket: w.relay.WebSocket, ...none });
  assert.equal(r.error, undefined);
  assert.equal(r.shortCode, await shortCode(w.machine.machinePub, r.device.publicRaw, w.offer.secret));
  assert.equal(r.deviceId, await deviceIdOf(r.device.publicRaw));
  assert.equal(r.passkey, false);
  assert.equal(r.device.deviceId, r.deviceId);
  assert.equal(r.device.machineId, w.offer.machineId);
  assert.deepEqual(r.device.machinePub, w.offer.machinePub);
  assert.equal(r.device.label, "Laptop");
  assert.equal(r.device.key.extractable, false);
  assert.equal(w.log.length, 1);
  assert.deepEqual(Object.keys(w.log[0]).sort(), ["device_pub", "label", "pair_id", "proof", "t"]);
});

test("a wrong code is refused", async () => {
  const w = await world({ wrongCode: true });
  const r = await pairOverHub({ offer: w.offer, label: "L", getTicket: w.getTicket, WebSocket: w.relay.WebSocket, ...none });
  assert.equal(r.error, CODES_DIFFER);
});

test("a bad label never opens a session", async () => {
  const w = await world();
  const r = await pairOverHub({ offer: w.offer, label: "", getTicket: w.getTicket, WebSocket: w.relay.WebSocket, ...none });
  assert.ok(r.error);
  assert.equal(w.count(), 0);
});

test("wrong machine signature is refused before the pair message", async () => {
  const w = await world();
  w.machine.faults.badSig = true;
  const r = await pairOverHub({ offer: w.offer, label: "L", getTicket: w.getTicket, WebSocket: w.relay.WebSocket, ...none });
  // The relay's check (4400 at the handshake) reads like the page's own.
  assert.equal(r.error, NOT_MACHINE);
  assert.deepEqual(w.relay.machineClosed, [4400]);
  assert.equal(w.log.length, 0);
  assert.equal(w.machine.seen.length, 0);
  // Only connect and the seal_hello left this page.
  const texts = w.relay.sent.filter((x) => typeof x === "string").map((x) => JSON.parse(x));
  assert.equal(texts.length, 2);
  assert.equal(texts[1].t, "msg");
});

test("a machine that is not the one in the offer is refused", async () => {
  const w = await world();
  const other = await fakeMachine({ offers: new Map([[w.offer.pairId, { secret: w.offer.secret }]]) });
  const relay = fakeRelay({ machine: other });
  const r = await pairOverHub({
    offer: w.offer, label: "L", getTicket: async () => relay.tickets.issue(), WebSocket: relay.WebSocket, ...none,
  });
  assert.equal(r.error, NOT_MACHINE);
  assert.equal(r.rule, "bad_answer");
  assert.equal(other.seen.length, 0);
});

test("a passkey is sent, and passkey_refused retries without it on the same session", async () => {
  const w = await world({ refusePasskey: true });
  const created = [];
  const r = await pairOverHub({
    offer: w.offer, label: "L", getTicket: w.getTicket, WebSocket: w.relay.WebSocket,
    credentials: fakeCredentials(created), hasPublicKey: true, hostname: "workspace.saiife.com",
  });
  assert.equal(r.error, undefined);
  assert.equal(r.passkey, false);
  assert.equal(created.length, 1);
  assert.equal(created[0].publicKey.rp.id, "workspace.saiife.com");
  assert.equal(w.log.length, 2);
  assert.ok(w.log[0].passkey);
  assert.equal("passkey" in w.log[1], false);
  assert.equal(w.count(), 1);
});

test("a passkey the machine takes is reported", async () => {
  const w = await world();
  const r = await pairOverHub({
    offer: w.offer, label: "L", getTicket: w.getTicket, WebSocket: w.relay.WebSocket,
    credentials: fakeCredentials([]), hasPublicKey: true, hostname: "workspace.saiife.com",
  });
  assert.equal(r.passkey, true);
  assert.equal(w.log.length, 1);
});

test("4402 on pairing says the Pro sentence", async () => {
  const w = await world();
  const r = await pairOverHub({
    offer: w.offer, label: "L", WebSocket: w.relay.WebSocket, ...none,
    getTicket: async () => w.relay.tickets.issue({ close: 4402 }),
  });
  assert.equal(r.error, PRO_SENTENCE);
  assert.equal(r.rule, "pro_required");
});

// A manual clock: schedule records, run() fires the next timer.
function clock() {
  const timers = [];
  const delays = [];
  let t = 0;
  return {
    schedule(fn, ms) {
      delays.push(ms);
      const x = { fn, at: t + ms };
      timers.push(x);
      return x;
    },
    cancel(x) {
      const i = timers.indexOf(x);
      if (i >= 0) timers.splice(i, 1);
    },
    now: () => t,
    delays,
    pending: () => timers.length,
    async fire() {
      const x = timers.shift();
      assert.ok(x, "a timer is pending");
      t = x.at;
      await x.fn();
      // let the async tick finish
      for (let i = 0; i < 200; i++) await new Promise((r) => setImmediate(r));
    },
  };
}

async function paired(w) {
  const r = await pairOverHub({ offer: w.offer, label: "L", getTicket: w.getTicket, WebSocket: w.relay.WebSocket, ...none });
  assert.equal(r.error, undefined);
  return r.device;
}

test("confirm wait ends done once the machine activates the device", async () => {
  const w = await world();
  const device = await paired(w);
  const c = clock();
  const ends = [];
  waitConfirmOverHub({
    device, getTicket: w.getTicket, WebSocket: w.relay.WebSocket,
    schedule: c.schedule, cancel: c.cancel, now: c.now, deadline: 10 * 60_000, onEnd: (e) => ends.push(e),
  });
  await c.fire();
  await c.fire();
  assert.deepEqual(ends, []);
  w.machine.pending.delete(device.deviceId);
  await c.fire();
  assert.deepEqual(ends, [{ kind: "done", passkey: false }]);
  assert.equal(c.pending(), 0);
});

test("confirm wait times out at the deadline and never saves", async () => {
  const w = await world();
  const device = await paired(w);
  const c = clock();
  const ends = [];
  const store = { saveDevice() { throw new Error("saved"); } };
  waitConfirmOverHub({
    device, store, getTicket: w.getTicket, WebSocket: w.relay.WebSocket,
    schedule: c.schedule, cancel: c.cancel, now: c.now, deadline: 2 * HUB_POLL_MS, onEnd: (e) => ends.push(e),
  });
  await c.fire();
  assert.deepEqual(ends, []);
  await c.fire();
  assert.deepEqual(ends, [{ kind: "timeout" }]);
  assert.equal(c.pending(), 0);
});

test("polls at most every 4 s", async () => {
  const w = await world();
  const device = await paired(w);
  const before = w.count();
  const c = clock();
  waitConfirmOverHub({
    device, getTicket: w.getTicket, WebSocket: w.relay.WebSocket,
    schedule: c.schedule, cancel: c.cancel, now: c.now, deadline: 60_000, onEnd: () => {},
  });
  for (let i = 0; i < 3; i++) await c.fire();
  assert.equal(HUB_POLL_MS, 4000);
  assert.ok(c.delays.every((d) => d >= 4000));
  assert.equal(w.count() - before, 3);
});

test("4404 means not yet", async () => {
  const w = await world();
  const device = await paired(w);
  const c = clock();
  const ends = [];
  waitConfirmOverHub({
    device, getTicket: async () => w.relay.tickets.issue({ close: 4404 }), WebSocket: w.relay.WebSocket,
    schedule: c.schedule, cancel: c.cancel, now: c.now, deadline: 60_000, onEnd: (e) => ends.push(e),
  });
  await c.fire();
  await c.fire();
  assert.deepEqual(ends, []);
  assert.equal(c.pending(), 1);
});

test("4402 on the confirm wait ends refused with the Pro sentence", async () => {
  const w = await world();
  const device = await paired(w);
  const c = clock();
  const ends = [];
  waitConfirmOverHub({
    device, getTicket: async () => w.relay.tickets.issue({ close: 4402 }), WebSocket: w.relay.WebSocket,
    schedule: c.schedule, cancel: c.cancel, now: c.now, deadline: 60_000, onEnd: (e) => ends.push(e),
  });
  await c.fire();
  assert.deepEqual(ends, [{ kind: "refused", message: PRO_SENTENCE }]);
  assert.equal(c.pending(), 0);
});

test("a wrong machine signature on the confirm wait ends refused", async () => {
  const w = await world();
  const device = await paired(w);
  w.machine.pending.delete(device.deviceId);
  w.machine.faults.badSig = true;
  const c = clock();
  const ends = [];
  waitConfirmOverHub({
    device, getTicket: w.getTicket, WebSocket: w.relay.WebSocket,
    schedule: c.schedule, cancel: c.cancel, now: c.now, deadline: 60_000, onEnd: (e) => ends.push(e),
  });
  await c.fire();
  assert.deepEqual(ends, [{ kind: "refused", message: NOT_MACHINE }]);
  assert.deepEqual(w.relay.machineClosed, [4400]);
  assert.equal(c.pending(), 0);
});

test("stop cancels the timer and nothing is reported", async () => {
  const w = await world();
  const device = await paired(w);
  const c = clock();
  const ends = [];
  const stop = waitConfirmOverHub({
    device, getTicket: w.getTicket, WebSocket: w.relay.WebSocket,
    schedule: c.schedule, cancel: c.cancel, now: c.now, deadline: 60_000, onEnd: (e) => ends.push(e),
  });
  stop();
  assert.equal(c.pending(), 0);
  assert.deepEqual(ends, []);
});

test("hubpair.js uses no storage", async () => {
  const { readFileSync } = await import("node:fs");
  const src = readFileSync(new URL("../js/hubpair.js", import.meta.url), "utf8");
  assert.ok(!/localStorage|sessionStorage|indexedDB|saveDevice/.test(src));
});
