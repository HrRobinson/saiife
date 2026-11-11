import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseFragment, proof, shortCode, pair, checkLabel, watchConfirm, POLL_MS } from "../js/pairing.js";
import { b64u, unb64u, deviceIdOf } from "../js/wire.js";
import { memoryStore } from "../js/keystore.js";

const vector = JSON.parse(
  readFileSync(new URL("../../../wire/tests/vectors/pair-v1.json", import.meta.url), "utf8"),
);
const enc = new TextEncoder();
const P256 = { name: "ECDSA", namedCurve: "P-256" };

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function machineIdOf(pub) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", pub))).slice(0, 32);
}

const SECRET = unb64u(vector.secret_b64u);
const MACHINE_PUB = unb64u(vector.machine_pub_b64u);
const MACHINE_ID = await machineIdOf(MACHINE_PUB);

// The offer as `wire::pair::fragment` encodes it (serde's sorted keys).
function offer(over = {}) {
  return {
    machine_id: MACHINE_ID,
    machine_pub: vector.machine_pub_b64u,
    pair_id: vector.pair_id,
    secret: vector.secret_b64u,
    v: 1,
    ...over,
  };
}
const frag = (text) => "#pair=" + b64u(enc.encode(text));
const GOOD = frag(JSON.stringify(offer()));

test("frozen pair vector", async () => {
  const devicePub = unb64u(vector.device_pub_b64u);
  assert.equal(b64u(await proof(SECRET, vector.pair_id, devicePub)), vector.proof_b64u);
  assert.equal(await shortCode(MACHINE_PUB, devicePub, SECRET), vector.short_code);
});

test("parseFragment reads a good offer", async () => {
  const p = await parseFragment(GOOD);
  assert.equal(p.pairId, vector.pair_id);
  assert.equal(p.machineId, MACHINE_ID);
  assert.deepEqual(p.secret, SECRET);
  assert.deepEqual(p.machinePub, MACHINE_PUB);
  assert.equal(p.secret.length, 32);
  assert.equal(p.machinePub.length, 65);
  // Key order does not matter (serde's preserve_order would change it).
  const o = offer();
  const reordered = { v: o.v, pair_id: o.pair_id, secret: o.secret, machine_id: o.machine_id, machine_pub: o.machine_pub };
  assert.notEqual(await parseFragment(frag(JSON.stringify(reordered))), null);
});

test("parseFragment rejects junk", async () => {
  const s = (o) => frag(JSON.stringify(o));
  const bad = [
    undefined,
    "",
    "#/pair",
    GOOD.replace("#pair=", "#/pair="),
    GOOD.replace("#pair=", "#pairs="),
    GOOD.slice(1), // no "#"
    "#pair=",
    "#pair=!!",
    GOOD + "=", // padding
    "#pair=ab+c",
    frag("not json"),
    frag("[1]"),
    frag("null"),
    s({ ...offer(), v: 2 }),
    s({ ...offer(), v: "1" }),
    s({ ...offer(), v: 1.5 }),
    s({ ...offer(), extra: "x" }),
    s((({ secret, ...rest }) => rest)(offer())),
    s(offer({ pair_id: b64u(new Uint8Array(7)) })),
    s(offer({ pair_id: b64u(new Uint8Array(9)) })),
    s(offer({ pair_id: 12345 })),
    s(offer({ secret: b64u(new Uint8Array(31)) })),
    s(offer({ secret: b64u(new Uint8Array(33)) })),
    s(offer({ secret: vector.secret_b64u + "=" })),
    s(offer({ machine_pub: b64u(MACHINE_PUB.subarray(0, 64)) })),
    s(offer({ machine_id: MACHINE_ID.toUpperCase() })),
    s(offer({ machine_id: "0".repeat(32) })),
    // Duplicate keys: the last value would win in JSON.parse.
    frag(JSON.stringify(offer()).replace('"v":1', '"v":1,"v":1')),
    frag(JSON.stringify(offer()).replace('"v":1', '"pair_id":"' + b64u(new Uint8Array(8)) + '","v":1')),
  ];
  for (const h of bad) {
    assert.equal(await parseFragment(h), null, String(h));
  }
});

test("labels follow the daemon's rule", () => {
  assert.equal(checkLabel("Browser on this machine"), null);
  assert.equal(checkLabel("é".repeat(40)), null);
  for (const l of ["", "a".repeat(41), "a\u202eb", "x\n", "\u200b", "a\u0000"]) {
    assert.notEqual(checkLabel(l), null, JSON.stringify(l));
  }
});

// The machine side in a box: /api/hello and /api/pair with the daemon's checks.
function fakeMachine({ machineId = MACHINE_ID, code = (c) => c, pairAnswer, log = [] } = {}) {
  const calls = [];
  const f = async (url, init = {}) => {
    log.push("fetch " + url);
    calls.push({ url, init });
    let status = 200;
    let payload;
    if (url === "/api/hello") {
      payload = { ok: true, result: { machine_id: machineId, machine_pub: vector.machine_pub_b64u, epoch: "e1", frame_version: 1 } };
    } else if (url === "/api/pair") {
      const b = JSON.parse(init.body);
      const devicePub = unb64u(b.device_pub);
      const want = b64u(await proof(SECRET, vector.pair_id, devicePub));
      if (pairAnswer) payload = pairAnswer;
      else if (b.proof !== want) payload = { ok: false, error: "forbidden", rule: "pair_proof", message: "wrong proof" };
      else {
        payload = {
          ok: true,
          result: { device_id: await deviceIdOf(devicePub), short_code: code(await shortCode(MACHINE_PUB, devicePub, SECRET)) },
        };
      }
    } else {
      status = 404;
      payload = { ok: false, error: "not_found" };
    }
    return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
  };
  f.calls = calls;
  return f;
}

function fakeHistory(log) {
  const calls = [];
  return {
    calls,
    replaceState(...a) {
      log.push("replaceState");
      calls.push(a);
    },
  };
}

const LOCATION = { pathname: "/", hash: GOOD };

test("pair posts the bodies the daemon expects and saves the device", async () => {
  const log = [];
  const fetch = fakeMachine({ log });
  const history = fakeHistory(log);
  const store = memoryStore();
  const r = await pair({ hash: GOOD, location: LOCATION, history, fetch, store, label: "my laptop" });
  assert.equal(typeof r.shortCode, "string", JSON.stringify(r));
  assert.match(r.shortCode, /^\d{3} \d{3}$/);
  const post = fetch.calls.find((c) => c.url === "/api/pair");
  assert.equal(post.init.method, "POST");
  assert.equal(post.init.headers["Content-Type"], "application/json");
  const body = JSON.parse(post.init.body);
  assert.deepEqual(Object.keys(body).sort(), ["device_pub", "label", "pair_id", "proof"]);
  assert.equal(body.pair_id, vector.pair_id);
  assert.equal(body.label, "my laptop");
  const rec = await store.loadDevice();
  assert.equal(rec.deviceId, r.deviceId);
  assert.equal(rec.machineId, MACHINE_ID);
  assert.equal(b64u(rec.publicRaw), body.device_pub);
  assert.equal(rec.key.extractable, false);
  assert.equal(rec.key.type, "private");
  await assert.rejects(crypto.subtle.exportKey("pkcs8", rec.key));
  assert.equal(r.shortCode, await shortCode(MACHINE_PUB, rec.publicRaw, SECRET));
});

test("fragment is cleared before posting", async () => {
  const log = [];
  const fetch = fakeMachine({ log });
  const history = fakeHistory(log);
  await pair({ hash: GOOD, location: LOCATION, history, fetch, store: memoryStore(), label: "x" });
  assert.equal(log[0], "replaceState");
  assert.ok(log.length > 1 && log.slice(1).every((e) => e.startsWith("fetch ")), log.join(","));
  assert.deepEqual(history.calls[0], [null, "", "/"]);
  // Junk is cleared too, and nothing is fetched.
  const log2 = [];
  const fetch2 = fakeMachine({ log: log2 });
  const r = await pair({ hash: "#pair=junk", location: LOCATION, history: fakeHistory(log2), fetch: fetch2, store: memoryStore(), label: "x" });
  assert.equal(typeof r.error, "string");
  assert.deepEqual(log2, ["replaceState"]);
});

test("machine id mismatch stops", async () => {
  const fetch = fakeMachine({ machineId: "f".repeat(32) });
  const store = memoryStore();
  const r = await pair({ hash: GOOD, location: LOCATION, history: fakeHistory([]), fetch, store, label: "x" });
  assert.equal(typeof r.error, "string");
  assert.match(r.error, /another machine/);
  assert.deepEqual(fetch.calls.map((c) => c.url), ["/api/hello"]);
  assert.equal(await store.loadDevice(), null);
});

async function oldDevice() {
  const k = await crypto.subtle.generateKey(P256, false, ["sign", "verify"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", k.publicKey));
  return { key: k.privateKey, publicRaw, deviceId: await deviceIdOf(publicRaw), machineId: MACHINE_ID };
}

test("codes that differ forget the key", async () => {
  const flip = (c) => (c[0] === "9" ? "0" : "9") + c.slice(1);
  const store = memoryStore();
  const r = await pair({ hash: GOOD, location: LOCATION, history: fakeHistory([]), fetch: fakeMachine({ code: flip }), store, label: "x" });
  assert.deepEqual(r, { error: "Codes differ: do not confirm on the machine" });
  assert.equal(await store.loadDevice(), null);
  // A browser that was paired before keeps its old device.
  const old = await oldDevice();
  await store.saveDevice(old);
  await pair({ hash: GOOD, location: LOCATION, history: fakeHistory([]), fetch: fakeMachine({ code: flip }), store, label: "x" });
  assert.equal(await store.loadDevice(), old);
});

test("a refusal shows the daemon's message and saves nothing", async () => {
  const store = memoryStore();
  const pairAnswer = { ok: false, error: "forbidden", rule: "pair_expired", message: "this pairing offer has expired" };
  const r = await pair({ hash: GOOD, location: LOCATION, history: fakeHistory([]), fetch: fakeMachine({ pairAnswer }), store, label: "x" });
  assert.equal(r.error, "this pairing offer has expired");
  assert.equal(r.rule, "pair_expired");
  assert.equal(await store.loadDevice(), null);
  // A device id that is not ours is refused as well.
  const other = { ok: true, result: { device_id: "d-0000000000000000", short_code: "000 000" } };
  const r2 = await pair({ hash: GOOD, location: LOCATION, history: fakeHistory([]), fetch: fakeMachine({ pairAnswer: other }), store, label: "x" });
  assert.equal(typeof r2.error, "string");
  assert.equal(await store.loadDevice(), null);
  // A bad label is refused before any request.
  const f3 = fakeMachine();
  const r3 = await pair({ hash: GOOD, location: LOCATION, history: fakeHistory([]), fetch: f3, store, label: "a\u202eb" });
  assert.equal(typeof r3.error, "string");
  assert.equal(f3.calls.length, 0);
});

test("link down is an error, not a throw", async () => {
  const fetch = async () => {
    throw new Error("down");
  };
  const r = await pair({ hash: GOOD, location: LOCATION, history: fakeHistory([]), fetch, store: memoryStore(), label: "x" });
  assert.equal(typeof r.error, "string");
});

// A fake clock and timer queue for watchConfirm.
function fakeTimers() {
  const t = { now: 0, queue: [], cancelled: 0 };
  t.schedule = (fn, ms) => {
    const id = { fn, at: t.now + ms };
    t.queue.push(id);
    return id;
  };
  t.cancel = (id) => {
    const i = t.queue.indexOf(id);
    if (i >= 0) {
      t.queue.splice(i, 1);
      t.cancelled++;
    }
  };
  // Runs the next timer and lets its promise chain settle.
  t.step = async () => {
    const next = t.queue.shift();
    if (!next) return false;
    t.now = next.at;
    await next.fn();
    return true;
  };
  return t;
}

function scriptedClient(answers) {
  const sent = [];
  return {
    sent,
    async send(action) {
      sent.push(action);
      return answers.length > 1 ? answers.shift() : answers[0];
    },
  };
}

const NOT_YET = { ok: false, error: "forbidden", rule: "unknown_device", message: "not paired" };
const PENDING = { ok: false, error: "forbidden", rule: "device_pending", message: "waits" };

test("watchConfirm polls whoami every 2 s until done", async () => {
  const t = fakeTimers();
  const client = scriptedClient([NOT_YET, PENDING, { ok: false, error: "unreachable", rule: null, message: "down" }, { ok: true, result: {} }]);
  const ends = [];
  watchConfirm({ client, schedule: t.schedule, cancel: t.cancel, now: () => t.now, deadline: 60000, onEnd: (e) => ends.push(e) });
  while (await t.step());
  assert.deepEqual(client.sent, Array(4).fill("workspace.whoami"));
  assert.equal(t.now, 4 * POLL_MS);
  assert.deepEqual(ends, [{ kind: "done" }]);
  assert.equal(t.queue.length, 0);
});

test("watchConfirm gives up at the deadline", async () => {
  const t = fakeTimers();
  const client = scriptedClient([NOT_YET]);
  const ends = [];
  watchConfirm({ client, schedule: t.schedule, cancel: t.cancel, now: () => t.now, deadline: 10000, onEnd: (e) => ends.push(e) });
  while (await t.step());
  assert.equal(client.sent.length, 5);
  assert.deepEqual(ends, [{ kind: "timeout" }]);
});

test("watchConfirm stops on a refusal with the daemon's message", async () => {
  const t = fakeTimers();
  const client = scriptedClient([{ ok: false, error: "forbidden", rule: "bad_signature", message: "the frame signature does not verify" }]);
  const ends = [];
  watchConfirm({ client, schedule: t.schedule, cancel: t.cancel, now: () => t.now, deadline: 60000, onEnd: (e) => ends.push(e) });
  while (await t.step());
  assert.deepEqual(ends, [{ kind: "refused", message: "the frame signature does not verify" }]);
  assert.equal(client.sent.length, 1);
});

test("watchConfirm leaves no timer behind when stopped", async () => {
  const t = fakeTimers();
  let release;
  const gate = new Promise((r) => (release = r));
  const client = { sent: 0, async send() { this.sent++; await gate; return NOT_YET; } };
  const ends = [];
  const stop = watchConfirm({ client, schedule: t.schedule, cancel: t.cancel, now: () => t.now, deadline: 60000, onEnd: (e) => ends.push(e) });
  stop();
  assert.equal(t.queue.length, 0);
  assert.equal(t.cancelled, 1);
  // Stopped while a request is in flight: its answer schedules nothing.
  const t2 = fakeTimers();
  const stop2 = watchConfirm({ client, schedule: t2.schedule, cancel: t2.cancel, now: () => t2.now, deadline: 60000, onEnd: (e) => ends.push(e) });
  const inflight = t2.step();
  stop2();
  release();
  await inflight;
  assert.equal(t2.queue.length, 0);
  assert.deepEqual(ends, []);
  stop2(); // twice is harmless
});
