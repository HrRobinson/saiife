// An in-memory relay for tests (and vendored verbatim in saiife.com): a
// WebSocket class that behaves like relay /v1/device (hub protocol v1, D2/D3)
// in front of a fakeMachine. Nothing here touches the network.
import { b64u, unb64u } from "./deps.mjs";

const enc = new TextEncoder();
const dec = new TextDecoder();
const DEVICE_ID = /^d-[0-9a-f]{16}$/;
const PAIR_ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_DATA = 1048576 + 24;
const MAX_FIRST = 4096;

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

// opts.connectWindowMs: how long a socket may stay silent before 4408 (5000).
export function fakeRelay({ machine, connectWindowMs = 5000 } = {}) {
  const sent = []; // every message a device sent: the raw text, or {binary: true}
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
    #phase = "connect"; // connect -> first -> open
    #session = null;
    #timer = null;
    #chain = Promise.resolve();

    constructor(url) {
      super();
      this.url = url;
      sockets.add(this);
      queueMicrotask(() => {
        if (this.readyState !== 0) return;
        this.readyState = 1;
        this.dispatchEvent(ev("open"));
        this.#timer = setTimeout(() => this.#shut(4408), connectWindowMs);
        this.#timer.unref?.();
      });
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
          typeof h.browser_eph === "string" &&
          (keysOf(h) === "browser_eph,device_id,t" && DEVICE_ID.test(h.device_id) ||
            keysOf(h) === "browser_eph,pair_id,t" && typeof h.pair_id === "string" && PAIR_ID.test(h.pair_id));
        if (!ok) return this.#shut(4400);
        this.#phase = "open";
      }
      const r = await this.#session.receive(bytes);
      for (const out of r.out) {
        this.#deliver(JSON.stringify({ t: "msg", data: b64u(out) }));
      }
      if (r.close) this.#shut(4000);
    }
  }

  return {
    WebSocket,
    tickets,
    sent,
    // Close every open device socket from the relay side.
    closeAll(code) {
      for (const s of [...sockets]) s.relayClose(code);
    },
  };
}
