// Pairing this browser with the machine (plan 28 pairing, plan 29 POST
// /api/pair). No DOM. The offer arrives in the URL fragment
// "#pair=<b64u(JSON)>"; it is removed from the address bar before any
// request, and the private key is generated non-extractable.
import { b64u, unb64u, deviceIdOf, Client } from "./wire.js";
import { ACTIONS, outcome } from "./actions.js";

export const PAIR_PROOF_DOMAIN = "saiife-pair-v1\n";
export const SHORT_CODE_DOMAIN = "saiife-pair-code-v1\n";
export const PASSKEY_CHALLENGE_DOMAIN = "saiife-pair-passkey-v1\n";
export const PASSKEY_DOMAIN = "saiife-pair-passkey-v1 sig\n";
export const NO_TOUCHES = "Touches are not available on this browser: approvals stay on the machine";
export const MAX_LABEL_CHARS = 40;
export const DEFAULT_LABEL = "Browser on this machine";
export const CODES_DIFFER = "Codes differ: do not confirm on the machine";
export const POLL_MS = 2000;
// The offer lives 300 s from `pair begin` (wire OFFER_TTL_SECS); waiting a
// little longer from our POST covers it whatever the clock skew.
export const WAIT_MS = 330 * 1000;

const P256 = { name: "ECDSA", namedCurve: "P-256" };
const enc = new TextEncoder();
const KEYS = ["machine_id", "machine_pub", "pair_id", "secret", "v"];
// Rust `char::is_control` (Cc) and the format characters touch's
// `check_label` refuses (Cf, plus the line and paragraph separators).
const HIDDEN = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

export const FRAGMENT_INVALID =
  "This pairing link is not valid. Run saiife workspace pair --local on the machine and open the link it prints.";

const SENTENCES = {
  fragment: FRAGMENT_INVALID,
  machine: "This pairing link is for another machine than this Workspace",
  answer: "The machine sent a pairing answer this page cannot read",
  crypto: "This browser cannot make a pairing key",
  store: "This browser could not keep the pairing key",
};

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function hex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function decodeN(s, n) {
  if (typeof s !== "string") return null;
  try {
    const b = unb64u(s);
    return b.length === n ? b : null;
  } catch {
    return null;
  }
}

// As strict as `wire::pair::parse_fragment`: exactly the five keys, v 1,
// the lengths, and machine_id = first 32 hex of SHA-256(machine_pub).
// Duplicate keys are refused: the text must be the compact JSON its parse
// prints again (a duplicate would print once). -> offer | null.
export async function parseFragment(hash) {
  if (typeof hash !== "string" || !hash.startsWith("#pair=")) return null;
  let text;
  let o;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(unb64u(hash.slice(6)));
    o = JSON.parse(text);
  } catch {
    return null;
  }
  if (o === null || typeof o !== "object" || Array.isArray(o)) return null;
  if (JSON.stringify(o) !== text) return null;
  const keys = Object.keys(o).sort();
  if (keys.length !== KEYS.length || keys.some((k, i) => k !== KEYS[i])) return null;
  if (o.v !== 1 || typeof o.pair_id !== "string" || typeof o.machine_id !== "string") return null;
  if (decodeN(o.pair_id, 8) === null) return null;
  const secret = decodeN(o.secret, 32);
  const machinePub = decodeN(o.machine_pub, 65);
  if (secret === null || machinePub === null) return null;
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", machinePub));
  if (hex(d.subarray(0, 16)) !== o.machine_id) return null;
  return { pairId: o.pair_id, secret, machineId: o.machine_id, machinePub };
}

// HMAC-SHA256(secret, PAIR_PROOF_DOMAIN ‖ pairId ASCII ‖ devicePub raw).
export async function proof(secret, pairId, devicePub) {
  const k = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const msg = concat(enc.encode(PAIR_PROOF_DOMAIN), enc.encode(pairId), devicePub);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
}

// "NNN NNN": SHA-256(domain ‖ machine_pub ‖ device_pub ‖ secret), the first
// four bytes big-endian, mod 1 000 000 (plan 28 `short_code`).
export async function shortCode(machinePub, devicePub, secret) {
  const msg = concat(enc.encode(SHORT_CODE_DOMAIN), machinePub, devicePub, secret);
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", msg));
  const n = (((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3]) % 1000000;
  const three = (x) => String(x).padStart(3, "0");
  return `${three(Math.floor(n / 1000))} ${three(n % 1000)}`;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

// The create challenge: SHA-256(PASSKEY_CHALLENGE_DOMAIN ‖ pairId ASCII ‖ devicePub).
export async function passkeyChallenge(pairId, devicePub) {
  return sha256(concat(enc.encode(PASSKEY_CHALLENGE_DOMAIN), enc.encode(pairId), devicePub));
}

// The options of navigator.credentials.create (plan 31 "Fixed values").
export function createOptions({ challenge, hostname, deviceId, label }) {
  return {
    publicKey: {
      challenge,
      rp: { id: hostname, name: "saiife" },
      user: { id: enc.encode(deviceId), name: label, displayName: label },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -8 },
      ],
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      attestation: "none",
      timeout: 120000,
    },
  };
}

// Makes a passkey for this pairing and has the device key sign it:
// ECDSA P-256 over PASSKEY_DOMAIN ‖ pairId ‖ credentialId ‖ SHA-256(authData)
// ‖ SHA-256(clientDataJSON). -> {credential_id, authenticator_data,
// client_data_json, device_sig} (base64url) | null when this browser cannot
// or the person declines (the pairing then goes on without touches).
export async function makePasskey({ credentials, hasPublicKey, hostname, pairId, publicRaw, deviceId, label, key }) {
  if (!hasPublicKey || !credentials || typeof credentials.create !== "function") return null;
  try {
    const challenge = await passkeyChallenge(pairId, publicRaw);
    const cred = await credentials.create(createOptions({ challenge, hostname, deviceId, label }));
    const r = cred && cred.response;
    if (!r || typeof r.getAuthenticatorData !== "function") return null;
    const credId = new Uint8Array(cred.rawId);
    const authData = new Uint8Array(r.getAuthenticatorData());
    const cdj = new Uint8Array(r.clientDataJSON);
    const msg = concat(
      enc.encode(PASSKEY_DOMAIN),
      enc.encode(pairId),
      credId,
      await sha256(authData),
      await sha256(cdj),
    );
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, msg));
    return {
      credential_id: b64u(credId),
      authenticator_data: b64u(authData),
      client_data_json: b64u(cdj),
      device_sig: b64u(sig),
    };
  } catch {
    return null;
  }
}

// null when the daemon would take the label, else the sentence why not.
export function checkLabel(label) {
  if (typeof label !== "string") return "A label is 1 to 40 characters";
  const n = [...label].length;
  if (n < 1 || n > MAX_LABEL_CHARS) return "A label is 1 to 40 characters";
  if (HIDDEN.test(label)) return "A label cannot contain control or invisible characters";
  return null;
}

// The whole pairing, in this order: parse, clear the fragment, check the
// machine, make the key, POST /api/pair, compare the codes. Nothing is
// saved here (ruling R-T3c): the new device is returned in memory, and
// `waitAndSave` saves it only once the owner confirmed on the machine.
// `store` is accepted for the brief's signature and never written.
// -> {deviceId, shortCode, device, passkey} | {error, rule?}
export async function pair({
  hash,
  location,
  history,
  fetch,
  store,
  label,
  credentials = globalThis.navigator && globalThis.navigator.credentials,
  hasPublicKey = typeof globalThis.PublicKeyCredential !== "undefined",
}) {
  const offer = await parseFragment(hash);
  // The secret leaves the address bar (and this history entry) first.
  history.replaceState(null, "", location.pathname);
  if (!offer) return { error: SENTENCES.fragment };
  const why = checkLabel(label);
  if (why) return { error: why };

  const client = new Client({ fetch, store });
  const hello = await client.hello();
  if (!hello.ok) return { error: hello.message, rule: hello.rule ?? hello.error };
  if (hello.result.machine_id !== offer.machineId) return { error: SENTENCES.machine };

  let keys;
  let publicRaw;
  let deviceId;
  let tag;
  let code;
  try {
    keys = await crypto.subtle.generateKey(P256, false, ["sign", "verify"]);
    publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
    deviceId = await deviceIdOf(publicRaw);
    tag = await proof(offer.secret, offer.pairId, publicRaw);
    code = await shortCode(offer.machinePub, publicRaw, offer.secret);
  } catch {
    return { error: SENTENCES.crypto };
  }

  let passkey = await makePasskey({
    credentials,
    hasPublicKey,
    hostname: location.hostname,
    pairId: offer.pairId,
    publicRaw,
    deviceId,
    label,
    key: keys.privateKey,
  });
  const post = (pk) =>
    client.request("/api/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pair_id: offer.pairId,
        device_pub: b64u(publicRaw),
        label,
        proof: b64u(tag),
        ...(pk ? { passkey: pk } : {}),
      }),
    });
  let a = await post(passkey);
  // The machine refused the passkey but not the pairing: go on without it.
  if (!a.ok && passkey && (a.rule ?? a.error) === "passkey_refused") {
    passkey = null;
    a = await post(null);
  }
  if (!a.ok) return { error: a.message, rule: a.rule ?? a.error };
  const r = a.result;
  if (!r || typeof r.device_id !== "string" || typeof r.short_code !== "string") {
    return { error: SENTENCES.answer };
  }
  // The key was never saved: dropping it here is forgetting it.
  if (r.short_code !== code) return { error: CODES_DIFFER };
  if (r.device_id !== deviceId) return { error: SENTENCES.answer };
  const device = { key: keys.privateKey, publicRaw, deviceId, machineId: offer.machineId };
  return { deviceId, shortCode: code, device, passkey: passkey !== null };
}

// Whether the daemon holds a passkey for this device: whoami's `passkeys`, a
// non-empty list of ids. Missing (a hub that strips it) or malformed: no.
export function holdsPasskey(result) {
  const p = result && typeof result === "object" ? result.passkeys : undefined;
  return Array.isArray(p) && p.length > 0 && p.every((x) => typeof x === "string" && x.length > 0);
}

// Polls workspace.whoami every POLL_MS until the owner confirms. While the
// owner has not, the daemon answers unknown_device (the device sits in the
// offer book, not the device list) or device_pending; both keep waiting,
// as does a link that is briefly down, until `deadline`. A rejection looks
// the same as not yet: it ends at the deadline. onEnd gets one of
// {kind:"done", passkey}, {kind:"timeout"}, {kind:"refused", message};
// `passkey` is the daemon's word (holdsPasskey), not the page's. Returns
// stop(): no timer and no callback survive it.
export function watchConfirm({ client, schedule = setTimeout, cancel = clearTimeout, now = Date.now, deadline, onEnd }) {
  let timer = null;
  let stopped = false;
  const end = (e) => {
    stopped = true;
    onEnd(e);
  };
  const tick = async () => {
    timer = null;
    if (stopped) return;
    const a = await client.send(ACTIONS.whoami);
    if (stopped) return;
    const o = outcome(a);
    if (o === "done") return end({ kind: "done", passkey: holdsPasskey(a.result) });
    if (o === "pending" || o === "unpaired" || o === "retry") {
      if (now() >= deadline) return end({ kind: "timeout" });
      timer = schedule(tick, POLL_MS);
      return;
    }
    end({ kind: "refused", message: a.message });
  };
  timer = schedule(tick, POLL_MS);
  return () => {
    stopped = true;
    if (timer !== null) cancel(timer);
    timer = null;
  };
}

// A store that holds one device in memory and never writes anywhere.
function holding(device) {
  return {
    async loadDevice() {
      return device;
    },
    async saveDevice() {
      throw new Error("read only");
    },
    async forgetDevice() {},
  };
}

// Waits for the owner's confirm with the new device held in memory, and
// saves it to `store` only on done. A timeout, a refusal or stop() drop
// it: whatever `store` held before (another pairing, another tab's) is
// untouched. onEnd as watchConfirm; a failed save ends "refused".
export function waitAndSave({ device, store, fetch, schedule, cancel, now, deadline, onEnd }) {
  const client = new Client({ fetch, store: holding(device) });
  let stopped = false;
  const stop = watchConfirm({
    client,
    schedule,
    cancel,
    now,
    deadline,
    onEnd: async (e) => {
      if (e.kind !== "done") return onEnd(e);
      try {
        await store.saveDevice(device);
      } catch {
        return onEnd({ kind: "refused", message: SENTENCES.store });
      }
      if (!stopped) onEnd(e);
    },
  });
  return () => {
    stopped = true;
    stop();
  };
}
