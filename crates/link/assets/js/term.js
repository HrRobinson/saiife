// The read-only terminal pane: box.term.read frames (plan 30 TermFrame,
// serde's external tags {"snapshot": {...}} / {"delta": {...}}) applied to a
// screen of plain lines, shown as text in one <pre>. Nothing in a line can
// act: no markup, no links, no buttons; escapes are shown, never run (§9.4).
import { visible } from "./format.js";

export const POLL_MS = 1000; // at most one read per second
export const ENDED = "The terminal has ended";
// What one pane shows at most, whatever a frame claims (10 000 lines/s
// cost the page nothing beyond this).
export const MAX_ROWS = 500;
export const MAX_COLS = 1000;

const SEQ = (x) => Number.isSafeInteger(x) && x >= 0;

function line(x) {
  return typeof x === "string" ? x.slice(0, MAX_COLS * 2) : "";
}

// -> {screen, gap}. A snapshot replaces the screen; a delta patches lines
// when its seq is the last + 1. Anything else (a gap, a delta before any
// snapshot, a frame this page cannot read) leaves the screen as it was and
// sets `gap`: the caller then asks for a fresh snapshot.
export function apply(screen, frame) {
  const s = frame && typeof frame === "object" ? frame.snapshot : undefined;
  if (s && typeof s === "object" && SEQ(s.seq) && Array.isArray(s.lines)) {
    return { screen: { seq: s.seq, lines: s.lines.slice(0, MAX_ROWS).map(line) }, gap: false };
  }
  const d = frame && typeof frame === "object" ? frame.delta : undefined;
  if (!screen || !d || typeof d !== "object" || !SEQ(d.seq) || d.seq !== screen.seq + 1 || !Array.isArray(d.lines)) {
    return { screen, gap: true };
  }
  const lines = screen.lines.slice();
  for (const p of d.lines) {
    if (!Array.isArray(p) || p.length !== 2) continue;
    const [row, text] = p;
    if (Number.isSafeInteger(row) && row >= 0 && row < lines.length) lines[row] = line(text);
  }
  return { screen: { seq: d.seq, lines }, gap: false };
}

// One line as the page shows it: visible() escapes, a newline inside the
// line shown as an escape too (it cannot draw a line of its own), cut at
// MAX_COLS characters.
function shown(s) {
  const v = visible(s).replace(/\n/g, "⟨U+000A⟩");
  const cs = Array.from(v);
  return cs.length > MAX_COLS ? cs.slice(0, MAX_COLS).join("") + "…" : v;
}

// -> a <pre> with one text node per line. `h` is dom.js's (strings become
// text nodes, never markup).
export function render(screen, h) {
  const lines = screen && Array.isArray(screen.lines) ? screen.lines : [];
  const n = lines.length;
  return h(
    "pre",
    { class: "term", "aria-label": "Terminal of the box, read only" },
    ...lines.map((l, i) => shown(l) + (i < n - 1 ? "\n" : "")),
  );
}

// Polls box.term.read for box `id`: the first read and the read after a
// gap ask with no `after` (a fresh snapshot), the others with `after` = the
// last seq. One read at a time and at most one per POLL_MS whatever ticks
// arrive; `ended` stops it. `schedule(fn, ms)`/`cancel` are setInterval /
// clearInterval; `onUpdate({screen, ended, error})` after every read.
export function poller({ client, id, schedule = setInterval, cancel = clearInterval, now = Date.now, onUpdate = () => {}, isVisible = () => true }) {
  let screen = null;
  let fresh = true; // the next read asks for a snapshot
  let last = -Infinity;
  let busy = null;
  let stopped = true;
  let ended = false;
  let timer = null;

  function halt() {
    if (timer !== null) cancel(timer);
    timer = null;
  }

  async function read() {
    const args = fresh || !screen ? { id } : { id, after: screen.seq };
    const a = await client.send("box.term.read", args);
    if (stopped) return;
    if (!a || !a.ok) {
      onUpdate({ screen, ended, error: a });
      return;
    }
    const r = a.result && typeof a.result === "object" ? a.result : {};
    fresh = false;
    for (const f of Array.isArray(r.frames) ? r.frames : []) {
      const x = apply(screen, f);
      if (x.gap) {
        fresh = true;
        break;
      }
      screen = x.screen;
    }
    if (r.ended === true) {
      ended = true;
      halt();
    }
    onUpdate({ screen, ended, error: null });
  }

  function tick() {
    if (stopped || ended || busy || !isVisible()) return busy ?? Promise.resolve();
    const t = now();
    if (t - last < POLL_MS) return Promise.resolve();
    last = t;
    busy = read()
      .catch(() => {})
      .finally(() => {
        busy = null;
      });
    return busy;
  }

  return {
    start() {
      if (!stopped) return;
      stopped = false;
      tick();
      timer = schedule(tick, POLL_MS);
    },
    stop() {
      stopped = true;
      halt();
    },
    tick,
    // Resolves when no read is in flight.
    idle() {
      return busy ?? Promise.resolve();
    },
    get screen() {
      return screen;
    },
    get ended() {
      return ended;
    },
  };
}
