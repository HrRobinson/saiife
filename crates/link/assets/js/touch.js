// A WebAuthn touch from the browser (plan 31, §8.3-§8.6): ask the daemon for
// a challenge bound to the action (workspace.touch.begin), show the short
// code, then the passkey dialog, then send the action with the assertion.
// A cancel, a timeout, an error or another passkey is "Not approved" and
// nothing is sent. There is no other way to approve: no password, no link.
import { b64u, unb64u } from "./wire.js";
import { touchNow, notApproved } from "./touchprompt.js";
import { holdsPasskey } from "./pairing.js";

export const PROMPT_TIMEOUT_MS = 120000; // saiife_touch::PROMPT_TIMEOUT_SECS × 1000
export const NOT_APPROVED = "Not approved";
export const BEGIN = "workspace.touch.begin";

const HEX32 = /^[0-9a-f]{64}$/;
const SHORT_CODE = /^[0-9]{6}$/;
const REQUEST_ID = /^[0-9]{1,20}$/;

function no(error, message, rule = null) {
  return { ok: false, error, rule, message };
}

const notApprovedAnswer = () => no("not_approved", NOT_APPROVED, "not_approved");
const badAnswer = () => no("bad_answer", "The Workspace link sent an answer this page cannot read");

function fromHex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// A touch request from the daemon, checked: the challenge 32 bytes of hex,
// a non-empty list of base64url ids, a 6-digit code. -> the request | null.
function checked(r) {
  if (!r || typeof r !== "object") return null;
  if (typeof r.challenge !== "string" || !HEX32.test(r.challenge)) return null;
  if (typeof r.short_code !== "string" || !SHORT_CODE.test(r.short_code)) return null;
  if (!Array.isArray(r.allow) || r.allow.length === 0) return null;
  try {
    for (const id of r.allow) if (unb64u(id).length === 0) return null;
  } catch {
    return null;
  }
  return {
    challenge: r.challenge,
    allow: r.allow.slice(),
    short_code: r.short_code,
    summary: typeof r.summary === "string" ? r.summary : "",
  };
}

// The fixed get options (plan 31 Fixed values).
export function getOptions(request, rpId) {
  return {
    publicKey: {
      challenge: fromHex(request.challenge),
      rpId,
      allowCredentials: request.allow.map((id) => ({ type: "public-key", id: unb64u(id) })),
      userVerification: "required",
      timeout: PROMPT_TIMEOUT_MS,
    },
  };
}

function bytes(x) {
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  throw new Error("not bytes");
}

// PublicKeyCredential -> the frame's TouchProof, base64url (wire TouchProof).
export function proofOf(requestId, credential) {
  const r = credential.response;
  return {
    request_id: String(requestId),
    credential_id: b64u(bytes(credential.rawId)),
    authenticator_data: b64u(bytes(r.authenticatorData)),
    client_data_json: b64u(bytes(r.clientDataJSON)),
    signature: b64u(bytes(r.signature)),
  };
}

// -> the answer of the touched frame, or a refusal: begin's own, a
// `bad_answer`, or `not_approved` (nothing sent). With `requestId`, begin is
// skipped and `request` ({challenge, allow, short_code, summary}) is the
// touch the daemon already issued (a pending land from the inbox). `mount`
// puts a prompt node on the page; it runs before the passkey dialog opens.
export async function touch(client, {
  action,
  args,
  requestId,
  request,
  credentials = globalThis.navigator && globalThis.navigator.credentials,
  rpId = globalThis.location && globalThis.location.hostname,
  mount = () => {},
} = {}) {
  let req;
  if (requestId === undefined || requestId === null) {
    const a = await client.send(BEGIN, { action, args });
    if (!a.ok) return a;
    req = checked(a.result);
    requestId = a.result && a.result.request_id;
  } else {
    req = checked(request);
  }
  if (!req || typeof requestId !== "string" || !REQUEST_ID.test(requestId)) return badAnswer();

  const what = { action, id: args && typeof args.id === "string" ? args.id : "", summary: req.summary };
  // The code is on the page before the dialog opens.
  mount(touchNow({ ...what, short_code: req.short_code }));
  let cred = null;
  try {
    if (!credentials || typeof credentials.get !== "function") throw new Error("no WebAuthn");
    cred = await credentials.get(getOptions(req, rpId));
  } catch {
    cred = null;
  }
  let proof = null;
  try {
    if (cred) {
      proof = proofOf(requestId, cred);
      // Another passkey than the daemon allowed: not this touch.
      if (!req.allow.includes(proof.credential_id)) proof = null;
    }
  } catch {
    proof = null;
  }
  if (!proof) {
    mount(notApproved(what));
    return notApprovedAnswer();
  }
  // Client.send resends this same proof once on stale_epoch, with a new body.
  return client.send(action, args, { touch: proof });
}

// The touch the daemon already issued for box `boxId`'s pending land (the
// inbox item: its request id, challenge and code), with the passkeys whoami
// lists. -> {requestId, request} | null when there is none or no passkey.
export async function pendingLand(client, boxId) {
  const inbox = await client.send("box.inbox", {});
  if (!inbox.ok) return null;
  const items = inbox.result && Array.isArray(inbox.result.items) ? inbox.result.items : [];
  const lands = items.filter((p) => p && p.class === "land" && p.box_id === boxId);
  if (lands.length === 0) return null;
  // The newest one, when the box has more than one.
  const it = lands.reduce((a, b) => (Number(b.created_at) > Number(a.created_at) ? b : a));
  const who = await client.send("workspace.whoami", {});
  if (!who.ok || !holdsPasskey(who.result)) return null;
  return {
    requestId: it.request_id,
    request: { challenge: it.challenge_hex, allow: who.result.passkeys, short_code: it.short_code, summary: it.summary },
  };
}
