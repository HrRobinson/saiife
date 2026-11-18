// The browser end of the hub seal (saiife-wire `seal`, hub protocol v1).
// No DOM; WebCrypto only. Byte-for-byte what crates/wire/src/seal.rs does:
// pinned by crates/wire/tests/vectors/seal-v1.json and machine-hello-v1.json.

export const HANDSHAKE_DOMAIN = "saiife-seal-v1 hello\n";
export const MACHINE_HELLO_DOMAIN = "saiife-seal-v1 machine\n";
export const SEAL_SALT = "saiife-seal-v1";
export const KEYS_INFO = "saiife-seal-v1 keys";
export const MAX_PLAINTEXT = 1048576;

const AAD_PREFIX = "saiife-seal-v1 ";
const TAG_LEN = 16;
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const enc = new TextEncoder();

// The relay is untrusted and supplies these: fixed sizes, never guessed.
function need(name, x, len) {
  if (!(x instanceof Uint8Array) || x.length !== len) throw new Error(`${name} must be ${len} bytes`);
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// A fresh ECDH P-256 key; the private half never leaves WebCrypto.
export async function newEphemeral() {
  const pair = await crypto.subtle.generateKey(ECDH, false, ["deriveBits"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicRaw };
}

// What the machine key signs: session_id ‖ machine_eph ‖ ("d:"|"p:") id.
export function machineHelloMsg(sessionId, machineEph, binding) {
  need("sessionId", sessionId, 16);
  need("machineEph", machineEph, 65);
  const hasDevice = typeof binding?.deviceId === "string";
  const hasPair = typeof binding?.pairId === "string";
  if (hasDevice === hasPair) throw new Error("binding is a deviceId or a pairId");
  const tag = hasDevice ? "d:" : "p:";
  return concat(sessionId, machineEph, enc.encode(tag + (hasDevice ? binding.deviceId : binding.pairId)));
}

// True only for a valid machine signature (domain-prefixed, raw r‖s).
export async function verifyMachineHello(machinePub, sessionId, machineEph, binding, sig64) {
  try {
    need("machinePub", machinePub, 65);
    need("sig", sig64, 64);
    const key = await crypto.subtle.importKey("raw", machinePub, ECDSA, false, ["verify"]);
    const msg = concat(enc.encode(MACHINE_HELLO_DOMAIN), machineHelloMsg(sessionId, machineEph, binding));
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig64, msg);
  } catch {
    return false;
  }
}

// The device key's seal_auth signature over session_id ‖ machine_eph ‖ browser_eph.
export async function handshakeSig(deviceKey, sessionId, machineEph, browserEph) {
  need("sessionId", sessionId, 16);
  need("machineEph", machineEph, 65);
  need("browserEph", browserEph, 65);
  const msg = concat(enc.encode(HANDSHAKE_DOMAIN), sessionId, machineEph, browserEph);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, deviceKey, msg);
  return new Uint8Array(sig);
}

// HKDF-SHA256: [0..32] browser to machine, [32..64] machine to browser.
export async function keysFromShared(shared, machineEph, browserEph, sessionId) {
  need("shared", shared, 32);
  need("machineEph", machineEph, 65);
  need("browserEph", browserEph, 65);
  need("sessionId", sessionId, 16);
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const info = concat(enc.encode(KEYS_INFO), machineEph, browserEph, sessionId);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(SEAL_SALT), info },
    ikm,
    512,
  );
  return new Uint8Array(bits);
}

function nonceFor(counter) {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(4, counter);
  return n;
}

const aadB = enc.encode(AAD_PREFIX + "b");
const aadM = enc.encode(AAD_PREFIX + "m");

// Browser end: seals direction b, opens direction m. Any failure to open
// kills the channel; a refused (too large) seal does not.
export class BrowserChannel {
  #tx;
  #rx;
  #nextTx = 0n;
  #nextRx = 0n;
  #dead = false;
  #queue = Promise.resolve();

  constructor(tx, rx) {
    this.#tx = tx;
    this.#rx = rx;
  }

  static async fromKeys(keys64) {
    if (!(keys64 instanceof Uint8Array) || keys64.length !== 64) throw new Error("keys are 64 bytes");
    const aes = (k) => crypto.subtle.importKey("raw", k, "AES-GCM", false, ["encrypt", "decrypt"]);
    return new BrowserChannel(await aes(keys64.slice(0, 32)), await aes(keys64.slice(32)));
  }

  async seal(plain) {
    if (this.#dead) throw new Error("channel closed");
    if (plain.length > MAX_PLAINTEXT) throw new Error("too large");
    // The counter is taken before any await so concurrent seals never share one.
    const counter = this.#nextTx++;
    try {
      const ct = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: nonceFor(counter), additionalData: aadB, tagLength: TAG_LEN * 8 },
          this.#tx,
          plain,
        ),
      );
      const head = new Uint8Array(8);
      new DataView(head.buffer).setBigUint64(0, counter);
      return concat(head, ct);
    } catch (e) {
      this.#dead = true;
      throw e;
    }
  }

  // Opens run one at a time so the strict counter check is never raced.
  open(sealed) {
    const run = this.#queue.then(() => this.#open(sealed));
    this.#queue = run.catch(() => {});
    return run;
  }

  async #open(sealed) {
    if (this.#dead) throw new Error("channel closed");
    try {
      if (sealed.length < 8 + TAG_LEN) throw new Error("too short");
      if (sealed.length > 8 + MAX_PLAINTEXT + TAG_LEN) throw new Error("too large");
      const counter = new DataView(sealed.buffer, sealed.byteOffset, 8).getBigUint64(0);
      if (counter !== this.#nextRx) throw new Error("out of order");
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonceFor(counter), additionalData: aadM, tagLength: TAG_LEN * 8 },
        this.#rx,
        sealed.subarray(8),
      );
      this.#nextRx = counter + 1n;
      return new Uint8Array(plain);
    } catch (e) {
      this.#dead = true;
      throw e;
    }
  }
}

// ECDH with the machine's ephemeral key, then the channel.
export async function finishBrowser({ privateKey, publicRaw }, machineEph, sessionId) {
  const peer = await crypto.subtle.importKey("raw", machineEph, ECDH, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256));
  return BrowserChannel.fromKeys(await keysFromShared(shared, machineEph, publicRaw, sessionId));
}
