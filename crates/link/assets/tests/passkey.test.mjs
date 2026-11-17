import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { pair, passkeyChallenge, PASSKEY_DOMAIN } from "../js/pairing.js";
import { b64u, unb64u } from "../js/wire.js";
import { memoryStore } from "../js/keystore.js";

const vector = JSON.parse(readFileSync(new URL("../../../wire/tests/vectors/pair-v1.json", import.meta.url), "utf8"));
const enc = new TextEncoder();
const MACHINE_PUB = unb64u(vector.machine_pub_b64u);
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const MACHINE_ID = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", MACHINE_PUB))).slice(0, 32);
const frag = "#pair=" + b64u(enc.encode(JSON.stringify({
  machine_id: MACHINE_ID, machine_pub: vector.machine_pub_b64u, pair_id: vector.pair_id, secret: vector.secret_b64u, v: 1,
})));
const LOCATION = { pathname: "/", hostname: "localhost", hash: frag };
const history = { replaceState() {} };

async function sha(b) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}

// A machine that records the /api/pair body and answers like the daemon
// (the answer's codes are computed from the posted key via pairing.js's own
// exports so pair() is not rejected for a code mismatch).
async function machine(bodies, { refusePasskey = false } = {}) {
  const { shortCode } = await import("../js/pairing.js");
  const { deviceIdOf } = await import("../js/wire.js");
  return async (url, init = {}) => {
    let payload;
    if (url === "/api/hello") {
      payload = { ok: true, result: { machine_id: MACHINE_ID, machine_pub: vector.machine_pub_b64u, epoch: "e", frame_version: 1 } };
    } else {
      const b = JSON.parse(init.body);
      bodies.push(b);
      if (refusePasskey && b.passkey) {
        payload = { ok: false, error: "bad_request", rule: "passkey_refused", message: "no" };
      } else {
        const pub = unb64u(b.device_pub);
        payload = { ok: true, result: { device_id: await deviceIdOf(pub), short_code: await shortCode(MACHINE_PUB, pub, unb64u(vector.secret_b64u)) } };
      }
    }
    return new Response(JSON.stringify(payload), { status: 200, headers: { "content-type": "application/json" } });
  };
}

function fakeCredentials(log) {
  const authData = Uint8Array.from({ length: 80 }, (_, i) => i + 1);
  const cdj = enc.encode('{"type":"webauthn.create"}');
  const rawId = Uint8Array.from([9, 8, 7, 6]);
  return {
    log,
    authData,
    cdj,
    rawId,
    async create(opts) {
      log.push(opts);
      return {
        rawId: rawId.buffer,
        response: {
          getAuthenticatorData: () => authData.buffer,
          clientDataJSON: cdj.buffer,
        },
      };
    },
  };
}

test("create options are as fixed", async () => {
  const log = [];
  const credentials = fakeCredentials(log);
  const bodies = [];
  const r = await pair({ hash: frag, location: LOCATION, history, fetch: await machine(bodies), store: memoryStore(), label: "my laptop", credentials, hasPublicKey: true });
  assert.ok(r.shortCode, JSON.stringify(r));
  assert.equal(log.length, 1);
  const pk = log[0].publicKey;
  assert.deepEqual(Object.keys(log[0]), ["publicKey"]);
  assert.deepEqual(pk.rp, { id: "localhost", name: "saiife" });
  assert.deepEqual(pk.user, { id: enc.encode(r.deviceId), name: "my laptop", displayName: "my laptop" });
  assert.deepEqual(pk.pubKeyCredParams, [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }]);
  assert.deepEqual(pk.authenticatorSelection, { userVerification: "required", residentKey: "preferred" });
  assert.equal(pk.attestation, "none");
  assert.equal(pk.timeout, 120000);
  assert.deepEqual(new Uint8Array(pk.challenge), await passkeyChallenge(vector.pair_id, r.device.publicRaw));
  // The challenge is SHA-256(domain ‖ pair_id ‖ device_pub).
  const want = await sha(new Uint8Array([...enc.encode("saiife-pair-passkey-v1\n"), ...enc.encode(vector.pair_id), ...r.device.publicRaw]));
  assert.deepEqual(new Uint8Array(pk.challenge), want);
  assert.equal(r.passkey, true);
  assert.deepEqual(Object.keys(bodies[0].passkey).sort(), ["authenticator_data", "client_data_json", "credential_id", "device_sig"]);
});

test("passkey is signed with the device key", async () => {
  const credentials = fakeCredentials([]);
  const bodies = [];
  const r = await pair({ hash: frag, location: LOCATION, history, fetch: await machine(bodies), store: memoryStore(), label: "x", credentials, hasPublicKey: true });
  const p = bodies[0].passkey;
  assert.equal(p.credential_id, b64u(credentials.rawId));
  assert.equal(p.authenticator_data, b64u(credentials.authData));
  assert.equal(p.client_data_json, b64u(credentials.cdj));
  // `passkey_sig_msg`'s layout: pair_id ‖ credential id ‖ SHA-256(authData) ‖ SHA-256(clientDataJSON).
  const msg = new Uint8Array([
    ...enc.encode(PASSKEY_DOMAIN),
    ...enc.encode(vector.pair_id),
    ...credentials.rawId,
    ...(await sha(credentials.authData)),
    ...(await sha(credentials.cdj)),
  ]);
  assert.equal(PASSKEY_DOMAIN, "saiife-pair-passkey-v1 sig\n");
  const pub = await crypto.subtle.importKey("raw", r.device.publicRaw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const sig = unb64u(p.device_sig);
  assert.equal(sig.length, 64);
  assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, sig, msg), true);
  // Not valid for another credential id.
  const other = new Uint8Array([...msg]);
  other[PASSKEY_DOMAIN.length + vector.pair_id.length] ^= 1;
  assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, sig, other), false);
});

test("no PublicKeyCredential pairs without passkey", async () => {
  const log = [];
  const bodies = [];
  const r = await pair({ hash: frag, location: LOCATION, history, fetch: await machine(bodies), store: memoryStore(), label: "x", credentials: fakeCredentials(log), hasPublicKey: false });
  assert.ok(r.shortCode, JSON.stringify(r));
  assert.equal(r.passkey, false);
  assert.equal(log.length, 0);
  assert.equal("passkey" in bodies[0], false);
});

test("NotAllowedError pairs without passkey", async () => {
  const bodies = [];
  const credentials = { async create() { throw new DOMException("no", "NotAllowedError"); } };
  const r = await pair({ hash: frag, location: LOCATION, history, fetch: await machine(bodies), store: memoryStore(), label: "x", credentials, hasPublicKey: true });
  assert.ok(r.shortCode, JSON.stringify(r));
  assert.equal(r.passkey, false);
  assert.equal("passkey" in bodies[0], false);
});

test("a refused passkey retries the pairing without it", async () => {
  const bodies = [];
  const r = await pair({ hash: frag, location: LOCATION, history, fetch: await machine(bodies, { refusePasskey: true }), store: memoryStore(), label: "x", credentials: fakeCredentials([]), hasPublicKey: true });
  assert.ok(r.shortCode, JSON.stringify(r));
  assert.equal(r.passkey, false);
  assert.equal(bodies.length, 2);
  assert.equal("passkey" in bodies[1], false);
});
