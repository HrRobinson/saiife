// The device end of one hub relay session (hub protocol v1, device side):
// the relay socket, the sealed handshake, and a `fetch` shim so the vendored
// Client from wire.js runs over it unchanged. No DOM; WebSocket is injected.
import { b64u, unb64u } from "./wire.js";
import { newEphemeral, verifyMachineHello, handshakeSig, finishBrowser } from "./seal.js";

// Close codes by number only; the reason string the relay sends is not used.
export const CLOSE = Object.freeze({
  4000: "closed_by_machine",
  4400: "bad_request",
  4401: "bad_ticket",
  4402: "pro_required",
  4404: "machine_unreachable",
  4408: "timeout",
  4410: "machine_reconnected",
  4413: "too_big",
  4429: "busy",
  1011: "internal_error",
  1012: "relay_restarting",
});

export class HubError extends Error {
  constructor(code, stage) {
    super(code);
    this.name = "HubError";
    this.code = code;
    this.stage = stage;
  }
}

export const CONNECT_MS = 10_000;
export const OPEN_MS = 15_000;
export const CALL_MS = 30_000;

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

function plainObject(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

function exactKeys(o, keys) {
  const k = Object.keys(o).sort();
  const want = [...keys].sort();
  return k.length === want.length && k.every((x, i) => x === want[i]);
}

// One relay session, single use: open() once, then call() for each sealed
// request. A new session needs a new ticket.
//
// getTicket() -> {ticket, url}: one fresh ticket from the BFF. For a known
// refusal it must throw HubError(code, "connect"): "pro_required" when the
// BFF answers 402, "signed_out" when it answers 401. Any other throw, or a
// malformed answer, becomes HubError("ticket_failed", "connect").
//
// open() resolves once the machine's signature verified and seal_auth was
// sent; the machine has not answered it yet, so the first call is what
// proves the device key (a refusal shows as a 4000 close). call() before
// open() resolved rejects HubError("not_open") and leaves the session be.
// onclose(err) fires once when the session ends on its own (relay close,
// timeout, bad answer); the owner's close() does not fire it.
export class HubSession {
  #getTicket;
  #machinePub;
  #binding;
  #deviceKey;
  #WS;
  #setTimeout;
  #clearTimeout;
  #ws = null;
  #used = false;
  #dead = false;
  #stage = "connect";
  #idle = false;
  #inbox = [];
  #waiter = null;
  #timers = new Set();
  #channel = null;
  #calls = Promise.resolve();
  #error = null;
  #death;
  #killed;
  onclose = () => {};

  constructor({
    getTicket,
    machinePub,
    binding,
    deviceKey,
    WebSocket = globalThis.WebSocket,
    setTimeout = globalThis.setTimeout,
    clearTimeout = globalThis.clearTimeout,
  }) {
    const isDevice = typeof binding?.deviceId === "string";
    const isPair = typeof binding?.pairId === "string";
    if (isDevice === isPair) throw new Error("binding is a deviceId or a pairId");
    if (isDevice && !deviceKey) throw new Error("a device binding needs deviceKey");
    this.#death = new Promise((_, rej) => {
      this.#killed = rej;
    });
    this.#death.catch(() => {});
    this.#getTicket = getTicket;
    this.#machinePub = machinePub;
    this.#binding = isDevice ? { deviceId: binding.deviceId } : { pairId: binding.pairId };
    this.#deviceKey = deviceKey;
    this.#WS = WebSocket;
    this.#setTimeout = (f, ms) => setTimeout(f, ms);
    this.#clearTimeout = (t) => clearTimeout(t);
  }

  // ---- lifecycle ----

  #timer(ms, fn) {
    const t = this.#setTimeout(fn, ms);
    this.#timers.add(t);
    return t;
  }

  #clear(t) {
    this.#clearTimeout(t);
    this.#timers.delete(t);
  }

  // The one way a session ends. onclose fires once; pending work rejects.
  #fail(err, local = false) {
    if (this.#dead) return;
    this.#dead = true;
    this.#error = err;
    for (const t of this.#timers) this.#clearTimeout(t);
    this.#timers.clear();
    const w = this.#waiter;
    this.#waiter = null;
    if (w) w.reject(err);
    this.#killed(err);
    try {
      if (this.#ws && this.#ws.readyState <= 1) this.#ws.close(1000);
    } catch {
      /* already closing */
    }
    if (!local) {
      try {
        this.onclose(err);
      } catch {
        /* a handler's throw is its own */
      }
    }
  }

  close() {
    this.#fail(new HubError("closed", this.#stage), true);
  }

  // ---- socket plumbing ----

  #onMessage(ev) {
    if (this.#dead) return;
    if (typeof ev.data !== "string") return; // binary is ignored
    if (this.#idle && !this.#waiter) {
      // An answer nobody asked for.
      this.#fail(new HubError("bad_answer", "open"));
      return;
    }
    if (this.#waiter) {
      const w = this.#waiter;
      this.#waiter = null;
      w.resolve(ev.data);
    } else {
      this.#inbox.push(ev.data);
    }
  }

  #onClose(ev) {
    this.#fail(new HubError(CLOSE[ev.code] ?? "closed", this.#stage));
  }

  #nextText() {
    if (this.#dead) return Promise.reject(this.#error);
    if (this.#inbox.length) return Promise.resolve(this.#inbox.shift());
    return new Promise((resolve, reject) => {
      this.#waiter = { resolve, reject };
    });
  }

  #send(obj) {
    const text = JSON.stringify(obj);
    if (this.#dead) throw this.#error;
    try {
      this.#ws.send(text);
    } catch {
      const e = new HubError("closed", this.#stage);
      this.#fail(e);
      throw e;
    }
  }

  // One relay `msg` envelope's data, strictly checked.
  async #nextData() {
    const text = await this.#nextText();
    let m;
    try {
      m = JSON.parse(text);
    } catch {
      m = null;
    }
    if (!plainObject(m) || m.t !== "msg" || !exactKeys(m, ["t", "data"]) || typeof m.data !== "string") {
      throw this.#bad();
    }
    try {
      return unb64u(m.data);
    } catch {
      throw this.#bad();
    }
  }

  #bad() {
    const e = new HubError("bad_answer", this.#stage);
    this.#fail(e);
    return e;
  }

  // ---- open ----

  async open() {
    if (this.#used) throw new Error("a session opens once");
    this.#used = true;
    try {
      // The death promise ends open() at once when a timer or a close kills
      // the session, even while an await with no waiter (getTicket) hangs.
      await Promise.race([this.#open(), this.#death]);
      if (this.#dead) throw this.#error;
    } catch (e) {
      if (!this.#dead) this.#fail(e instanceof HubError ? e : new HubError("closed", this.#stage));
      throw this.#error;
    }
  }

  async #open() {
    const whole = this.#timer(OPEN_MS, () => this.#fail(new HubError("timeout", this.#stage)));
    const connectT = this.#timer(CONNECT_MS, () => this.#fail(new HubError("timeout", "connect")));

    let t;
    try {
      t = await this.#getTicket();
    } catch (e) {
      throw e instanceof HubError ? e : new HubError("ticket_failed", "connect");
    }
    if (this.#dead) throw this.#error;
    if (!t || typeof t.ticket !== "string" || typeof t.url !== "string") {
      throw new HubError("ticket_failed", "connect");
    }
    const ws = new this.#WS(t.url);
    this.#ws = ws;
    ws.addEventListener("message", (ev) => this.#onMessage(ev));
    ws.addEventListener("close", (ev) => this.#onClose(ev));
    ws.addEventListener("error", () => this.#fail(new HubError("connection_failed", this.#stage)));
    await new Promise((resolve, reject) => {
      if (ws.readyState === 1) return resolve();
      ws.addEventListener("open", () => resolve());
      this.#waiter = { resolve: () => {}, reject };
      // A close or error before open goes through #fail, which rejects this.
    });
    this.#waiter = null;
    this.#send({ t: "connect", v: 1, ticket: t.ticket });

    const ready = await this.#nextText();
    let r;
    try {
      r = JSON.parse(ready);
    } catch {
      r = null;
    }
    if (!plainObject(r) || r.t !== "ready" || !exactKeys(r, ["t", "session"]) || typeof r.session !== "string") {
      throw this.#bad();
    }
    this.#clear(connectT);
    this.#stage = "handshake";

    const eph = await newEphemeral();
    const hello = { t: "seal_hello", browser_eph: b64u(eph.publicRaw) };
    if ("deviceId" in this.#binding) hello.device_id = this.#binding.deviceId;
    else hello.pair_id = this.#binding.pairId;
    this.#sendData(hello);

    const bytes = await this.#nextData();
    let m;
    try {
      m = JSON.parse(dec.decode(bytes));
    } catch {
      m = null;
    }
    if (
      !plainObject(m) ||
      m.t !== "seal_hello" ||
      !exactKeys(m, ["t", "machine_eph", "session_id", "machine_sig"]) ||
      typeof m.machine_eph !== "string" ||
      typeof m.session_id !== "string" ||
      typeof m.machine_sig !== "string"
    ) {
      throw this.#bad();
    }
    let machineEph, sessionId, sig;
    try {
      machineEph = unb64u(m.machine_eph);
      sessionId = unb64u(m.session_id);
      sig = unb64u(m.machine_sig);
    } catch {
      throw this.#bad();
    }
    if (machineEph.length !== 65 || sessionId.length !== 16 || sig.length !== 64) throw this.#bad();
    // Before anything else leaves this page: is this the machine we paired with?
    if (!(await verifyMachineHello(this.#machinePub, sessionId, machineEph, this.#binding, sig))) {
      throw this.#bad();
    }
    if (this.#dead) throw this.#error;
    // The channel first: a machine_eph that is not a point sends nothing more.
    let channel;
    try {
      channel = await finishBrowser(eph, machineEph, sessionId);
    } catch {
      throw this.#bad();
    }
    if (this.#dead) throw this.#error;
    if ("deviceId" in this.#binding) {
      const auth = await handshakeSig(this.#deviceKey, sessionId, machineEph, eph.publicRaw);
      if (this.#dead) throw this.#error;
      this.#sendData({ t: "seal_auth", sig: b64u(auth) });
    }
    this.#channel = channel;
    this.#stage = "open";
    this.#idle = true;
    this.#clear(whole);
  }

  #sendData(obj) {
    this.#send({ t: "msg", data: b64u(enc.encode(JSON.stringify(obj))) });
  }

  // ---- calls ----

  // One sealed request, its one sealed answer. Calls run one at a time, in
  // the order made; nothing else is sealed while one is in flight.
  call(obj) {
    const run = this.#calls.then(() => this.#call(obj));
    this.#calls = run.catch(() => {});
    return run;
  }

  async #call(obj) {
    if (this.#dead) throw this.#error;
    if (!this.#channel) throw new HubError("not_open", this.#stage);
    const timer = this.#timer(CALL_MS, () => this.#fail(new HubError("timeout", "open")));
    try {
      const sealed = await this.#channel.seal(enc.encode(JSON.stringify(obj)));
      if (this.#dead) throw this.#error;
      this.#send({ t: "msg", data: b64u(sealed) });
      // The waiter is registered in this same tick as the send, so the answer
      // is never taken for an unasked message.
      const data = await this.#nextData();
      let plain;
      try {
        plain = await this.#channel.open(data);
      } catch {
        throw this.#bad();
      }
      let a;
      try {
        a = JSON.parse(dec.decode(plain));
      } catch {
        a = null;
      }
      if (!plainObject(a) || a.t !== "result") throw this.#bad();
      return a;
    } catch (e) {
      if (!this.#dead) this.#fail(e instanceof HubError ? e : new HubError("closed", "open"));
      throw this.#error;
    } finally {
      this.#clear(timer);
    }
  }

}

// ---- the fetch shim ----

function json(status, obj) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}

// The local server's answer (crates/link/src/local.rs answer()): 200, but
// 503 for an unreachable daemon, so Client says the same sentence.
function answer(a) {
  const { t: _t, ...rest } = a;
  return json(rest.ok === false && rest.error === "unreachable" ? 503 : 200, rest);
}

// A `fetch` for the vendored Client: /api/hello and /api/frame become sealed
// requests on the session; the sealed result is the local server's answer.
// A HubError other than pro_required makes the fetch REJECT, like a failed
// network fetch, so Client says "The Workspace link is not reachable" (a 503
// would read as "The saiife daemon is not reachable"). pro_required answers
// 402 {"error":"pro_required"}; other paths 404.
export function hubFetch(getSession) {
  return async (url, init = {}) => {
    const path = String(url).split("?")[0];
    const method = (init.method ?? "GET").toUpperCase();
    let req;
    if (path === "/api/hello" && method === "GET") {
      req = { t: "hello" };
    } else if (path === "/api/frame" && method === "POST") {
      let f;
      try {
        f = JSON.parse(init.body);
      } catch {
        return json(400, { error: "bad_request" });
      }
      if (!plainObject(f) || typeof f.body !== "string" || typeof f.sig !== "string") {
        return json(400, { error: "bad_request" });
      }
      req = { t: "frame", body: f.body, sig: f.sig };
      if (f.touch !== undefined && f.touch !== null) req.touch = f.touch;
    } else {
      return json(404, { error: "not_found" });
    }
    try {
      const s = await getSession();
      return answer(await s.call(req));
    } catch (e) {
      if (e instanceof HubError && e.code === "pro_required") return json(402, { error: "pro_required" });
      throw e;
    }
  };
}
