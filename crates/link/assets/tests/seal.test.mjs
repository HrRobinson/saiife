// seal.js against the frozen vectors (crates/wire/tests/vectors).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { b64u, unb64u } from "../js/wire.js";
import * as seal from "../js/seal.js";

const dir = new URL("../../../wire/tests/vectors/", import.meta.url);
const sv = JSON.parse(readFileSync(new URL("seal-v1.json", dir), "utf8"));
const mh = JSON.parse(readFileSync(new URL("machine-hello-v1.json", dir), "utf8"));
const unhex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const hex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");
const enc = new TextEncoder();
const dec = new TextDecoder();

const machineEph = unb64u(sv.machine_eph);
const browserEph = unb64u(sv.browser_eph);
const sessionId = unb64u(sv.session_id);
const keys = () => seal.keysFromShared(unhex(sv.shared_secret_hex), machineEph, browserEph, sessionId);

test("keys from the vector's shared secret", async () => {
  assert.equal(hex(await keys()), sv.keys_hex);
});

test("constants are the frozen strings", () => {
  assert.equal(seal.HANDSHAKE_DOMAIN, "saiife-seal-v1 hello\n");
  assert.equal(seal.MACHINE_HELLO_DOMAIN, "saiife-seal-v1 machine\n");
  assert.equal(seal.SEAL_SALT, "saiife-seal-v1");
  assert.equal(seal.KEYS_INFO, "saiife-seal-v1 keys");
  assert.equal(seal.MAX_PLAINTEXT, 1048576);
});

test("seal and open every vector message", async () => {
  const ch = await seal.BrowserChannel.fromKeys(await keys());
  for (const m of sv.messages) {
    if (m.dir === "b") {
      assert.equal(b64u(await ch.seal(enc.encode(m.plaintext))), m.sealed_b64u);
    } else {
      assert.equal(dec.decode(await ch.open(unb64u(m.sealed_b64u))), m.plaintext);
    }
  }
});

test("out of order and tampered fail and kill the channel", async () => {
  const msgs = sv.messages.filter((m) => m.dir === "m");
  const a = await seal.BrowserChannel.fromKeys(await keys());
  await assert.rejects(a.open(unb64u(msgs[1].sealed_b64u)));
  await assert.rejects(a.open(unb64u(msgs[0].sealed_b64u)), "dead after a failure");

  const b = await seal.BrowserChannel.fromKeys(await keys());
  const bad = unb64u(msgs[0].sealed_b64u);
  bad[bad.length - 1] ^= 1;
  await assert.rejects(b.open(bad));
  await assert.rejects(b.open(unb64u(msgs[0].sealed_b64u)));
  await assert.rejects(b.seal(enc.encode("x")));
});

test("a replayed message fails", async () => {
  const msgs = sv.messages.filter((m) => m.dir === "m");
  const ch = await seal.BrowserChannel.fromKeys(await keys());
  await ch.open(unb64u(msgs[0].sealed_b64u));
  await assert.rejects(ch.open(unb64u(msgs[0].sealed_b64u)));
});

test("too large refuses", async () => {
  const ch = await seal.BrowserChannel.fromKeys(await keys());
  await assert.rejects(ch.seal(new Uint8Array(seal.MAX_PLAINTEXT + 1)));
  // The limit itself is fine, and a refusal does not kill the channel.
  assert.equal((await ch.seal(new Uint8Array(seal.MAX_PLAINTEXT))).length, 8 + seal.MAX_PLAINTEXT + 16);
});

test("machine hello vectors", async () => {
  const sid = unb64u(mh.session_id_b64u);
  const eph = unb64u(mh.machine_eph_b64u);
  const pub = unb64u(mh.machine_pub_b64u);
  const dev = { deviceId: mh.device_id };
  const pair = { pairId: mh.pair_id };
  assert.equal(hex(seal.machineHelloMsg(sid, eph, dev)), mh.machine_hello_device_hex);
  assert.equal(hex(seal.machineHelloMsg(sid, eph, pair)), mh.machine_hello_pair_hex);
  const dsig = unb64u(mh.machine_hello_device_sig_b64u);
  const psig = unb64u(mh.machine_hello_pair_sig_b64u);
  assert.equal(await seal.verifyMachineHello(pub, sid, eph, dev, dsig), true);
  assert.equal(await seal.verifyMachineHello(pub, sid, eph, pair, psig), true);
  assert.equal(await seal.verifyMachineHello(pub, sid, eph, pair, dsig), false);
  assert.equal(await seal.verifyMachineHello(pub, sid, eph, dev, psig), false);
  assert.equal(await seal.verifyMachineHello(pub, sid, eph, dev, new Uint8Array(3)), false);
});

test("handshake signature verifies over session, machine and browser eph", async () => {
  const P256 = { name: "ECDSA", namedCurve: "P-256" };
  const kp = await crypto.subtle.generateKey(P256, false, ["sign", "verify"]);
  const sig = await seal.handshakeSig(kp.privateKey, sessionId, machineEph, browserEph);
  assert.equal(sig.length, 64);
  const msg = new Uint8Array([...enc.encode(seal.HANDSHAKE_DOMAIN), ...sessionId, ...machineEph, ...browserEph]);
  assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, kp.publicKey, sig, msg), true);
});

test("two ends derive the same channel", async () => {
  const m = await seal.newEphemeral();
  const b = await seal.newEphemeral();
  assert.equal(b.publicRaw.length, 65);
  const sid = crypto.getRandomValues(new Uint8Array(16));
  const ch = await seal.finishBrowser(b, m.publicRaw, sid);
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", public: await crypto.subtle.importKey("raw", b.publicRaw, { name: "ECDH", namedCurve: "P-256" }, false, []) }, m.privateKey, 256),
  );
  const k = await seal.keysFromShared(shared, m.publicRaw, b.publicRaw, sid);
  const twin = await seal.BrowserChannel.fromKeys(k);
  assert.deepEqual(await ch.seal(enc.encode("hi")), await twin.seal(enc.encode("hi")));
});
