// An in-memory relay for tests (and vendored verbatim in saiife.com): a
// WebSocket class that behaves like relay /v1/device (hub protocol v1, D2/D3)
// in front of a fakeMachine. Nothing here touches the network.
//
// What it does like the real relay: connect within the window (4408), the
// single-use ticket (4401), a per-ticket refusal after connect (any code,
// e.g. 4402 or 4404), the strict envelopes and the first device message
// (4400, including a 65-byte browser_eph), a binary first message (4400),
// a device msg before the machine's seal_hello (4400), the machine's
// seal_hello checked against the machine key over session_id ‖ machine_eph
// ‖ "d:"/"p:" id under the machine-hello domain (both ways 4400 when bad),
// the handshake window from `ready` (4408), the data size (4413), and the
// machine ending the session (4000). `closeAll(code)` stands in for a link
// replaced (4410), a relay restart (1012) or a plan recheck (4402).
//
// What it leaves out: claiming, so an unclaimed machine reached with a
// device_id is not refused 4404 (a test asks for 4404 by ticket); the plan
// and quota recheck every 300 s; rate limits and the session cap (4429);
// backpressure (4413); the WebSocket's own 1009 for a message over 2 MiB;
// pings; ticket expiry after 60 s; the Origin check.
import { b64u, unb64u, machineHelloMsg, MACHINE_HELLO_DOMAIN } from "./deps.mjs";

const enc = new TextEncoder();
const dec = new TextDecoder();
const DEVICE_ID = /^d-[0-9a-f]{16}$/;
const PAIR_ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_DATA = 1048576 + 24;
const MAX_FIRST = 4096;
const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const SIG = { name: "ECDSA", hash: "SHA-256" };

function ev(type, props = {}) {
  const e = new Event(type);
  Object.assign(e, props);
  return e;
}

function obj(text) {
  try {
    const v = JSON.parse(text);
    return v !== null && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

const keysOf = (o) => Object.keys(o).sort().join(",");

function cat(...ps) {
  const out = new Uint8Array(ps.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of ps) {
    out.set(p, at);
    at += p.length;
  }
  return out;
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

// The relay's check of the machine's first message for a session.
async function machineHelloOk(machinePub, bytes, binding) {
  const h = bytes.length <= MAX_FIRST ? obj(dec.decode(bytes)) : null;
  if (!h || h.t !== "seal_hello" || keysOf(h) !== "machine_eph,machine_sig,session_id,t") return false;
  const eph = decodeN(h.machine_eph, 65);
  const sid = decodeN(h.session_id, 16);
  const sig = decodeN(h.machine_sig, 64);
  if (!eph || !sid || !sig) return false;
  try {
    const key = await crypto.subtle.importKey("raw", machinePub, ECDSA, false, ["verify"]);
    const msg = cat(enc.encode(MACHINE_HELLO_DOMAIN), machineHelloMsg(sid, eph, binding));
    return await crypto.subtle.verify(SIG, key, sig, msg);
  } catch {
    return false;
  }
}

// opts.connectWindowMs: how long a socket may stay silent before 4408 (5000).
// opts.handshakeWindowMs: from `ready` to the machine's checked seal_hello,
//   else 4408 (15000).
// opts.checkMachineHello: false forwards the machine's seal_hello unchecked,
//   a relay that lies, so a test reaches the page's own checks (true).
export function fakeRelay({ machine, connectWindowMs = 5000, handshakeWindowMs = 15000, checkMachineHello = true } = {}) {
  const sent = []; // every message a device sent: the raw text, or {binary: true}
  const machineClosed = []; // close codes the relay sent the machine for a session
  const sockets = new Set();
  const used = new Set();
  const live = new Map(); // ticket -> {close?: code}
  let n = 0;

  const tickets = {
    // A fresh single-use ticket; `close` makes the relay refuse after connect.
    issue({ close } = {}) {
      const ticket = `ticket-${++n}-${b64u(crypto.getRandomValues(new Uint8Array(6)))}`;
      live.set(ticket, { close });
      return { ticket, url: "wss://relay.test/v1/device" };
    },
    used,
    live,
  };

  class WebSocket extends EventTarget {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    readyState = 0;
    #phase = "connect"; // connect -> first -> machine -> open
    #session = null;
    #binding = null;
    #timer = null;
    #texts = 0; // text messages the device sent
    #machineSeen = false; // the machine's seal_hello was checked and passed on
    #chain = Promise.resolve();

    constructor(url) {
      super();
      this.url = url;
      sockets.add(this);
      queueMicrotask(() => {
        if (this.readyState !== 0) return;
        this.readyState = 1;
        this.dispatchEvent(ev("open"));
        this.#arm(connectWindowMs);
      });
    }

    #arm(ms) {
      clearTimeout(this.#timer);
      this.#timer = setTimeout(() => this.#shut(4408), ms);
      this.#timer.unref?.();
    }

    // device -> relay
    send(data) {
      if (this.readyState !== 1) throw new Error("not open");
      if (typeof data !== "string") {
        sent.push({ binary: true });
        if (this.#phase === "connect" || this.#phase === "first") this.#shut(4400);
        return;
      }
      sent.push(data);
      // connect, then the device's seal_hello; anything more before the
      // machine's seal_hello arrived is refused on arrival.
      if (++this.#texts > 2 && !this.#machineSeen) return this.#shut(4400);
      this.#chain = this.#chain.then(() => this.#onText(data)).catch(() => this.#shut(1011));
    }

    close(code = 1000) {
      if (this.readyState >= 2) return;
      this.#end(code, true);
    }

    // relay -> device, one microtask later like a real socket
    #deliver(text) {
      queueMicrotask(() => {
        if (this.readyState === 1) this.dispatchEvent(ev("message", { data: text }));
      });
    }

    // The relay ends this socket with a close code (tests: closeAll).
    relayClose(code) {
      this.#shut(code);
    }

    #shut(code) {
      if (this.readyState >= 2) return;
      this.#end(code, false);
    }

    #end(code, byDevice) {
      clearTimeout(this.#timer);
      sockets.delete(this);
      this.readyState = 3;
      queueMicrotask(() => this.dispatchEvent(ev("close", { code: byDevice ? 1000 : code, reason: "", wasClean: true })));
    }

    async #onText(text) {
      if (this.readyState !== 1) return;
      if (this.#phase === "connect") {
        const m = obj(text);
        if (!m || keysOf(m) !== "t,ticket,v" || m.t !== "connect" || m.v !== 1 || typeof m.ticket !== "string") {
          return this.#shut(4400);
        }
        const t = live.get(m.ticket);
        if (!t || used.has(m.ticket)) return this.#shut(4401);
        used.add(m.ticket);
        live.delete(m.ticket);
        clearTimeout(this.#timer);
        if (t.close) return this.#shut(t.close);
        this.#session = machine.session();
        this.#phase = "first";
        this.#arm(handshakeWindowMs);
        this.#deliver(JSON.stringify({ t: "ready", session: b64u(crypto.getRandomValues(new Uint8Array(16))) }));
        return;
      }
      const m = obj(text);
      if (!m || keysOf(m) !== "data,t" || m.t !== "msg" || typeof m.data !== "string") return this.#shut(4400);
      let bytes;
      try {
        bytes = unb64u(m.data);
      } catch {
        return this.#shut(4400);
      }
      if (bytes.length > MAX_DATA) return this.#shut(4413);
      if (this.#phase === "first") {
        const h = bytes.length <= MAX_FIRST ? obj(dec.decode(bytes)) : null;
        const ok =
          h &&
          h.t === "seal_hello" &&
          decodeN(h.browser_eph, 65) !== null &&
          ((keysOf(h) === "browser_eph,device_id,t" && typeof h.device_id === "string" && DEVICE_ID.test(h.device_id)) ||
            (keysOf(h) === "browser_eph,pair_id,t" && typeof h.pair_id === "string" && PAIR_ID.test(h.pair_id)));
        if (!ok) return this.#shut(4400);
        this.#binding = "device_id" in h ? { deviceId: h.device_id } : { pairId: h.pair_id };
        this.#phase = "machine";
      }
      const r = await this.#session.receive(bytes);
      for (const out of r.out) {
        if (this.readyState !== 1) return;
        if (this.#phase === "machine") {
          if (checkMachineHello && !(await machineHelloOk(machine.machinePub, out, this.#binding))) {
            machineClosed.push(4400);
            return this.#shut(4400);
          }
          if (this.readyState !== 1) return;
          clearTimeout(this.#timer);
          this.#machineSeen = true;
          this.#phase = "open";
        }
        this.#deliver(JSON.stringify({ t: "msg", data: b64u(out) }));
      }
      if (r.close) this.#shut(4000);
    }
  }

  return {
    WebSocket,
    tickets,
    sent,
    machineClosed,
    // Close every open device socket from the relay side.
    closeAll(code) {
      for (const s of [...sockets]) s.relayClose(code);
    },
  };
}
