// Pairing over the hub (hub protocol v1, device side). No DOM, no storage:
// the new device is returned in memory and the caller keeps it only once
// waitConfirmOverHub reports done. WebSocket and timers are injected.
import { b64u, deviceIdOf, Client } from "./wire.js";
import { ACTIONS, outcome } from "./actions.js";
import { checkLabel, proof, shortCode, makePasskey, holdsPasskey, CODES_DIFFER } from "./pairing.js";
import { HubSession, HubError, hubFetch } from "./hubsession.js";

// 15 tickets a minute, under the hub's 30 a minute per user.
export const HUB_POLL_MS = 4000;

export const PRO_SENTENCE =
  "Your trial has ended. Workspace over the internet needs Pro. The Workspace on localhost stays free.";
const LINK = "The Workspace link is not reachable";
const SIGN_IN = "Sign in to saiife first, then open the pairing link again";
const NOT_MACHINE = "The connection to the machine could not be verified";
const ANSWER = "The machine sent a pairing answer this page cannot read";
const CRYPTO = "This browser cannot make a pairing key";

const P256 = { name: "ECDSA", namedCurve: "P-256" };

// The machine did not prove itself: the page's own check (bad_answer), or
// the relay's check of machine_sig, which closes 4400 at the handshake.
function notMachine(e) {
  return e instanceof HubError && (e.code === "bad_answer" || (e.code === "bad_request" && e.stage === "handshake"));
}

// getTicket's refusal when the BFF answers 401 (see HubSession).
function signedOut(e) {
  return e instanceof HubError && e.code === "signed_out" && e.stage === "connect";
}

function hubFail(e) {
  if (e instanceof HubError && e.code === "pro_required") return { error: PRO_SENTENCE, rule: "pro_required" };
  if (notMachine(e)) return { error: NOT_MACHINE, rule: "bad_answer" };
  if (signedOut(e)) return { error: SIGN_IN, rule: "signed_out" };
  return { error: LINK, rule: "unreachable" };
}

// The whole pairing over one pairing-only session bound to offer.pairId.
// The device key and the passkey are made at call time, the user's tap
// (iOS lets credentials.create run only then), while the session opens.
// Nothing is sent until the machine proves itself by its signature
// (machinePub from the offer); if it does not, the key and the passkey are
// dropped unsent. Nothing is saved.
// -> {deviceId, shortCode, device, passkey} | {error, rule?}
export async function pairOverHub({
  offer,
  label,
  getTicket,
  credentials = globalThis.navigator && globalThis.navigator.credentials,
  hasPublicKey = typeof globalThis.PublicKeyCredential !== "undefined",
  hostname = globalThis.location && globalThis.location.hostname,
  WebSocket = globalThis.WebSocket,
}) {
  const why = checkLabel(label);
  if (why) return { error: why };
  const session = new HubSession({ getTicket, machinePub: offer.machinePub, binding: { pairId: offer.pairId }, WebSocket });
  // Started now, all three at once; awaited in order below.
  const opened = session.open();
  opened.catch(() => {});
  const made = (async () => {
    const keys = await crypto.subtle.generateKey(P256, false, ["sign", "verify"]);
    const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
    const deviceId = await deviceIdOf(publicRaw);
    return { keys, publicRaw, deviceId };
  })();
  made.catch(() => {});
  const madePasskey = made.then(
    ({ keys, publicRaw, deviceId }) =>
      makePasskey({ credentials, hasPublicKey, hostname, pairId: offer.pairId, publicRaw, deviceId, label, key: keys.privateKey }),
    () => null,
  );
  try {
    try {
      await opened;
    } catch (e) {
      return hubFail(e);
    }

    let keys, publicRaw, deviceId, tag, code;
    try {
      ({ keys, publicRaw, deviceId } = await made);
      tag = await proof(offer.secret, offer.pairId, publicRaw);
      code = await shortCode(offer.machinePub, publicRaw, offer.secret);
    } catch {
      return { error: CRYPTO };
    }

    let passkey = await madePasskey;
    const send = (pk) =>
      session.call({
        t: "pair",
        pair_id: offer.pairId,
        device_pub: b64u(publicRaw),
        label,
        proof: b64u(tag),
        ...(pk ? { passkey: pk } : {}),
      });
    let a;
    try {
      a = await send(passkey);
      // The machine refused the passkey but not the pairing: go on without it.
      if (a.ok !== true && passkey && (a.rule ?? a.error) === "passkey_refused") {
        passkey = null;
        a = await send(null);
      }
    } catch (e) {
      return hubFail(e);
    }
    if (a.ok !== true) {
      const rule = a.rule ?? a.error;
      const message = typeof a.message === "string" && a.message.length > 0 ? a.message : ANSWER;
      return { error: message, ...(typeof rule === "string" ? { rule } : {}) };
    }
    const r = a.result;
    if (!r || typeof r.device_id !== "string" || typeof r.short_code !== "string") return { error: ANSWER };
    if (r.short_code !== code) return { error: CODES_DIFFER };
    if (r.device_id !== deviceId) return { error: ANSWER };
    const device = {
      key: keys.privateKey,
      publicRaw,
      deviceId,
      machineId: offer.machineId,
      machinePub: offer.machinePub,
      label,
    };
    return { deviceId, shortCode: code, device, passkey: passkey !== null };
  } finally {
    session.close();
  }
}

// A store that holds one device in memory and has no way to write.
function holding(device) {
  return {
    async loadDevice() {
      return device;
    },
    async forgetDevice() {},
  };
}

// Every HUB_POLL_MS a new device session is opened (one ticket each; a
// HubSession is single use) and asked workspace.whoami. A close before the
// machine's seal_hello or a 4404 (the machine has not made the device
// active yet) means "not yet", as does an answer of pending or unknown.
// 4402 ends refused with the Pro sentence; a machine that does not prove
// itself, signed out and a refused ticket (4401) end refused too: polling
// would not change them. Returns stop(). Nothing is saved.
// onEnd gets {kind:"done", passkey} | {kind:"timeout"} | {kind:"refused", message}.
export function waitConfirmOverHub({
  device,
  getTicket,
  schedule = setTimeout,
  cancel = clearTimeout,
  now = Date.now,
  deadline,
  onEnd,
  WebSocket = globalThis.WebSocket,
}) {
  let timer = null;
  let stopped = false;
  let current = null;
  const end = (e) => {
    stopped = true;
    onEnd(e);
  };
  const notYet = () => {
    if (now() >= deadline) return end({ kind: "timeout" });
    timer = schedule(tick, HUB_POLL_MS);
  };
  const step = async () => {
    timer = null;
    if (stopped) return;
    const session = new HubSession({
      getTicket,
      machinePub: device.machinePub,
      binding: { deviceId: device.deviceId },
      deviceKey: device.key,
      WebSocket,
    });
    current = session;
    try {
      try {
        await session.open();
      } catch (e) {
        if (stopped) return;
        if (e instanceof HubError && e.code === "pro_required") return end({ kind: "refused", message: PRO_SENTENCE });
        if (notMachine(e)) return end({ kind: "refused", message: NOT_MACHINE });
        if (signedOut(e)) return end({ kind: "refused", message: SIGN_IN });
        if (e instanceof HubError && e.code === "bad_ticket" && e.stage === "connect") {
          return end({ kind: "refused", message: LINK });
        }
        return notYet();
      }
      // The Client turns a dead session into "not reachable"; keep the why.
      let died = null;
      const shim = hubFetch(async () => session);
      const fetch = async (url, init) => {
        try {
          return await shim(url, init);
        } catch (e) {
          died = e;
          throw e;
        }
      };
      const client = new Client({ fetch, store: holding(device) });
      const a = await client.send(ACTIONS.whoami);
      if (stopped) return;
      // A sealed answer that does not open is not the machine.
      if (notMachine(died)) return end({ kind: "refused", message: NOT_MACHINE });
      const o = outcome(a);
      if (o === "done") return end({ kind: "done", passkey: holdsPasskey(a.result) });
      if (o === "pending" || o === "unpaired" || o === "retry") return notYet();
      if ((a.rule ?? a.error) === "pro_required") return end({ kind: "refused", message: PRO_SENTENCE });
      end({ kind: "refused", message: a.message });
    } finally {
      session.close();
      if (current === session) current = null;
    }
  };
  // A throw (onEnd's own included) never becomes an unhandled rejection;
  // unless the wait has ended, it counts as "not yet".
  const tick = () =>
    step().catch(() => {
      if (stopped) return;
      try {
        notYet();
      } catch {
        /* onEnd's throw is its own */
      }
    });
  timer = schedule(tick, HUB_POLL_MS);
  return () => {
    stopped = true;
    if (timer !== null) cancel(timer);
    timer = null;
    if (current) current.close();
  };
}
