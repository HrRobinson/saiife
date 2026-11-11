// Signed frames from the browser to the localhost link (plan 28 Frame).
// No DOM. Every answer is {ok:true, result} or {ok:false, error, rule, message};
// views key on `rule ?? error` (see actions.js `outcome`).
import * as keystore from "./keystore.js";

export const SIG_DOMAIN = "saiife-wire-v1\n";
export const TTL_SECS = 120; // under plan 28's MAX_TTL_SECS (300)
export const FRAME_VERSION = 1;
export const MAX_BODY_BYTES = 64 * 1024;

const enc = new TextEncoder();
const B64U = /^[A-Za-z0-9_-]*$/;

// base64url without padding (the only base64 on the wire).
export function b64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Strict decode: padding, the standard alphabet or a dangling char throws.
export function unb64u(s) {
  if (typeof s !== "string" || !B64U.test(s) || s.length % 4 === 1) {
    throw new Error("not base64url");
  }
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  // Non-canonical trailing bits would decode the same as another string.
  if (b64u(out) !== s) throw new Error("not base64url");
  return out;
}

function hex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

// "d-" + the first 16 hex of SHA-256(raw public key).
export async function deviceIdOf(publicRaw) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", publicRaw));
  return "d-" + hex(d.subarray(0, 8));
}

// 16 random bytes, b64u (wire verify decodes exactly 16).
export function newNonce() {
  return b64u(crypto.getRandomValues(new Uint8Array(16)));
}

function plainObject(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x) &&
    Object.getPrototypeOf(x) === Object.prototype;
}

// The plan 28 Frame as JSON, fields in its order. `now` is unix seconds.
export function buildBody({ machineId, epoch, deviceId, action, args = {}, now, nonce = newNonce() }) {
  if (!plainObject(args)) throw new Error("args must be an object");
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("now must be unix seconds");
  return JSON.stringify({
    v: FRAME_VERSION,
    machine_id: String(machineId),
    epoch: String(epoch),
    device_id: String(deviceId),
    action: String(action),
    args,
    nonce,
    issued_at: now,
    expires_at: now + TTL_SECS,
  });
}

// b64u of the raw r‖s (P1363) signature over SIG_DOMAIN ‖ utf8(body).
export async function sign(key, body) {
  const b = enc.encode(body);
  const d = enc.encode(SIG_DOMAIN);
  const m = new Uint8Array(d.length + b.length);
  m.set(d, 0);
  m.set(b, d.length);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, m);
  return b64u(new Uint8Array(sig));
}

const SENTENCES = {
  unreachable: "The saiife daemon is not reachable",
  link: "The Workspace link is not reachable",
  refused: "The Workspace link refused the request",
  bad: "The Workspace link sent an answer this page cannot read",
  unpaired: "This browser is no longer paired",
  large: "The request is too large to send",
};

const NAME = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_MESSAGE = 500;

function no(error, message, rule = null) {
  return { ok: false, error, rule, message };
}

// Reads one HTTP answer into the one answer shape. Raw text never leaks.
async function readAnswer(res) {
  let v;
  try {
    v = JSON.parse(await res.text());
  } catch {
    v = undefined;
  }
  if (res.status === 503) return no("unreachable", SENTENCES.unreachable);
  const named = v && typeof v.error === "string" && NAME.test(v.error) ? v.error : null;
  if (res.status !== 200) return no(named ?? "bad_answer", SENTENCES.refused);
  if (v && v.ok === true && "result" in v) return { ok: true, result: v.result };
  if (v && v.ok === false && named) {
    const rule = typeof v.rule === "string" && NAME.test(v.rule) ? v.rule : null;
    const message =
      typeof v.message === "string" && v.message.length > 0
        ? v.message.slice(0, MAX_MESSAGE)
        : SENTENCES.refused;
    return no(named, message, rule);
  }
  return no("bad_answer", SENTENCES.bad);
}

export class Client {
  constructor({ fetch, store, now } = {}) {
    this.fetch = fetch ?? ((u, i) => globalThis.fetch(u, i));
    this.store = store ?? keystore;
    this.now = now ?? (() => Math.floor(Date.now() / 1000));
    this.cached = null;
  }

  async request(url, init) {
    try {
      return await readAnswer(await this.fetch(url, { cache: "no-store", ...init }));
    } catch {
      return no("unreachable", SENTENCES.link);
    }
  }

  // GET /api/hello; only a good answer is cached.
  async hello() {
    if (this.cached) return this.cached;
    const a = await this.request("/api/hello", { method: "GET" });
    if (a.ok) {
      const r = a.result;
      if (!r || typeof r.machine_id !== "string" || typeof r.epoch !== "string") {
        return no("bad_answer", SENTENCES.bad);
      }
      this.cached = a;
    }
    return a;
  }

  async attempt(device, action, args, touch) {
    const h = await this.hello();
    if (!h.ok) return h;
    let body;
    try {
      body = buildBody({
        machineId: h.result.machine_id,
        epoch: h.result.epoch,
        deviceId: device.deviceId,
        action,
        args,
        now: this.now(),
      });
    } catch {
      return no("invalid", SENTENCES.refused);
    }
    if (enc.encode(body).length > MAX_BODY_BYTES) return no("too_large", SENTENCES.large);
    const frame = { body, sig: await sign(device.key, body) };
    if (touch !== undefined && touch !== null) frame.touch = touch;
    return this.request("/api/frame", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(frame),
    });
  }

  // One frame; on stale_epoch the hello is refetched and the frame rebuilt
  // with a new nonce, once.
  async send(action, args = {}, opts = {}) {
    let device = null;
    try {
      device = await this.store.loadDevice();
    } catch {
      device = null;
    }
    if (!device) return no("unknown_device", SENTENCES.unpaired);
    const first = await this.attempt(device, action, args, opts.touch);
    if (first.ok || first.rule !== "stale_epoch") return first;
    this.cached = null;
    return this.attempt(device, action, args, opts.touch);
  }
}
