// The machine end of the hub handshake, for tests (and vendored verbatim in
// saiife.com). WebCrypto only; no network.
//
// Built from: seal.js's vector-tested machineHelloMsg and keysFromShared for
// the signed message and the key schedule; everything else (the ECDH, the
// machine_sig, the seal_auth check, and above all the machine-end channel
// that seals direction "m" and opens direction "b") is written here
// independently of BrowserChannel, so a browser/machine disagreement shows.
import { machineHelloMsg, keysFromShared, HANDSHAKE_DOMAIN, MACHINE_HELLO_DOMAIN, b64u, unb64u, deviceIdOf } from "./deps.mjs";

const enc = new TextEncoder();
const dec = new TextDecoder();
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const SIG = { name: "ECDSA", hash: "SHA-256" };

function cat(...ps) {
  const out = new Uint8Array(ps.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of ps) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function nonce(counter) {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(4, counter);
  return n;
}

// Machine end: seals with the m key (second half), opens with the b key.
class MachineChannel {
  constructor(bKey, mKey) {
    this.bKey = bKey;
    this.mKey = mKey;
    this.tx = 0n;
    this.rx = 0n;
  }

  static async from(keys64) {
    const aes = (k) => crypto.subtle.importKey("raw", k, "AES-GCM", false, ["encrypt", "decrypt"]);
    return new MachineChannel(await aes(keys64.slice(0, 32)), await aes(keys64.slice(32)));
  }

  async seal(plain) {
    const c = this.tx++;
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce(c), additionalData: enc.encode("saiife-seal-v1 m"), tagLength: 128 },
        this.mKey,
        plain,
      ),
    );
    const head = new Uint8Array(8);
    new DataView(head.buffer).setBigUint64(0, c);
    return cat(head, ct);
  }

  async open(sealed) {
    const c = new DataView(sealed.buffer, sealed.byteOffset, 8).getBigUint64(0);
    if (c !== this.rx) throw new Error("out of order");
    const p = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce(c), additionalData: enc.encode("saiife-seal-v1 b"), tagLength: 128 },
      this.bKey,
      sealed.subarray(8),
    );
    this.rx = c + 1n;
    return new Uint8Array(p);
  }
}

const DEVICE_ID = /^d-[0-9a-f]{16}$/;
const PAIR_ID = /^[A-Za-z0-9_-]{1,64}$/;

function parse(bytes) {
  try {
    const v = JSON.parse(dec.decode(bytes));
    return v !== null && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

const keysOf = (o) => Object.keys(o).sort().join(",");

// `devices`: Map deviceId -> publicRaw; `offers`: Map pairId -> {secret};
// `pending`: Set of deviceIds known but not yet approved; `answers(plain)`:
// the result for a sealed hello/frame/pair (an object merged under
// {"t":"result"}). `faults` may be changed by a test at any time:
//   sigFor: a binding to sign for instead of the real one,
//   extraKey: add a key to the machine's seal_hello,
//   badSig: flip a byte of machine_sig,
//   rawReply: send these bytes (a Uint8Array) as the machine's first reply,
//   badEph: send (and sign) a machine_eph that is not a P-256 point,
//   badSeal: flip a byte of each sealed answer.
export async function fakeMachine({
  devices = new Map(),
  offers = new Map(),
  pending = new Set(),
  answers = async () => ({ ok: true, result: {} }),
} = {}) {
  const pair = await crypto.subtle.generateKey(ECDSA, false, ["sign", "verify"]);
  const machinePub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const faults = {};
  const seen = []; // every plaintext the machine opened, in order

  async function signHello(sid, meph, binding) {
    const msg = cat(enc.encode(MACHINE_HELLO_DOMAIN), machineHelloMsg(sid, meph, binding));
    const sig = new Uint8Array(await crypto.subtle.sign(SIG, pair.privateKey, msg));
    if (faults.badSig) sig[0] ^= 1;
    return sig;
  }

  // One relay session. receive(bytes) -> {out: [Uint8Array], close: bool}.
  function session() {
    let step = 0;
    let st = null;
    const closed = { out: [], close: true };
    let chain = Promise.resolve();

    async function hello(bytes) {
      const m = parse(bytes);
      if (!m || m.t !== "seal_hello" || typeof m.browser_eph !== "string") return closed;
      const hasD = "device_id" in m;
      const hasP = "pair_id" in m;
      if (hasD === hasP || keysOf(m) !== ["browser_eph", hasD ? "device_id" : "pair_id", "t"].sort().join(",")) {
        return closed;
      }
      let beph;
      try {
        beph = unb64u(m.browser_eph);
      } catch {
        return closed;
      }
      if (beph.length !== 65) return closed;
      let binding;
      if (hasD) {
        if (!DEVICE_ID.test(m.device_id) || pending.has(m.device_id) || !devices.has(m.device_id)) return closed;
        binding = { deviceId: m.device_id };
      } else {
        if (!PAIR_ID.test(m.pair_id) || !offers.has(m.pair_id)) return closed;
        binding = { pairId: m.pair_id };
      }
      const eph = await crypto.subtle.generateKey(ECDH, false, ["deriveBits"]);
      const meph = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
      const sid = crypto.getRandomValues(new Uint8Array(16));
      const peer = await crypto.subtle.importKey("raw", beph, ECDH, false, []);
      const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, eph.privateKey, 256));
      const keys = await keysFromShared(shared, meph, beph, sid);
      const sentEph = faults.badEph ? Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 4 : 1)) : meph;
      const sig = await signHello(sid, sentEph, faults.sigFor ?? binding);
      const reply = { t: "seal_hello", machine_eph: b64u(sentEph), session_id: b64u(sid), machine_sig: b64u(sig) };
      if (faults.extraKey) reply.extra = "x";
      st = { binding, beph, meph, sid, keys };
      step = hasD ? 1 : 2;
      const out = faults.rawReply ? faults.rawReply : enc.encode(JSON.stringify(reply));
      if (hasP) st.channel = await MachineChannel.from(keys);
      return { out: [out], close: false };
    }

    async function auth(bytes) {
      const m = parse(bytes);
      if (!m || m.t !== "seal_auth" || keysOf(m) !== "sig,t" || typeof m.sig !== "string") return closed;
      let sig;
      try {
        sig = unb64u(m.sig);
      } catch {
        return closed;
      }
      if (sig.length !== 64) return closed;
      const pub = devices.get(st.binding.deviceId);
      const key = await crypto.subtle.importKey("raw", pub, ECDSA, false, ["verify"]);
      const msg = cat(enc.encode(HANDSHAKE_DOMAIN), st.sid, st.meph, st.beph);
      if (!(await crypto.subtle.verify(SIG, key, sig, msg))) return closed;
      st.channel = await MachineChannel.from(st.keys);
      step = 2;
      return { out: [], close: false };
    }

    async function sealed(bytes) {
      let plain;
      try {
        plain = parse(await st.channel.open(bytes));
      } catch {
        return closed;
      }
      if (!plain || typeof plain.t !== "string") return closed;
      seen.push(plain);
      const isDevice = "deviceId" in st.binding;
      let res;
      if (isDevice && (plain.t === "hello" || plain.t === "frame")) {
        res = await answers(plain, st.binding);
      } else if (!isDevice && plain.t === "pair" && plain.pair_id === st.binding.pairId) {
        res = await answers(plain, st.binding);
      } else {
        return closed;
      }
      const out = await st.channel.seal(enc.encode(JSON.stringify({ t: "result", ...res })));
      if (faults.badSeal) out[out.length - 1] ^= 1;
      return { out: [out], close: false };
    }

    return {
      // Messages are handled one at a time, in arrival order.
      receive(bytes) {
        const run = chain.then(async () => {
          if (step === 0) return hello(bytes);
          if (step === 1) return auth(bytes);
          return sealed(bytes);
        });
        chain = run.catch(() => {});
        return run.catch(() => closed);
      },
    };
  }

  return { machinePub, devices, offers, pending, faults, seen, session, deviceIdOf };
}
