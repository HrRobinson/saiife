// Pure helpers for the overview and steer screens. No DOM.

export const TASK_PREVIEW_CHARS = 140;
export const MAX_STEER_BYTES = 4096;

const gb = (mb) => (mb / 1024).toFixed(1);

// "N running · M queued · K free slots · CPU x% · RAM a/b GB"; load may be null.
export function headerLine(ov) {
  const boxes = Array.isArray(ov?.boxes) ? ov.boxes : [];
  const n = (s) => boxes.filter((b) => b.state === s).length;
  const parts = [`${n("running")} running`, `${n("queued")} queued`, `${ov?.slots_free ?? 0} free slots`];
  const l = ov?.load;
  if (l) {
    parts.push(`CPU ${l.cpu_pct}%`);
    parts.push(`RAM ${gb(l.mem_used_mb)}/${gb(l.mem_total_mb)} GB`);
  }
  return parts.join(" · ");
}

// First 140 characters (by code point) and whether the text was cut.
export function preview(text) {
  const chars = Array.from(String(text ?? ""));
  if (chars.length <= TASK_PREVIEW_CHARS) return { text: chars.join(""), cut: false };
  return { text: chars.slice(0, TASK_PREVIEW_CHARS).join(""), cut: true };
}

const STATES = new Set(["queued", "starting", "running", "paused", "done", "landed", "discarded"]);

// The badge class: only a known state names one; anything else is neutral.
export function stateClass(state) {
  return typeof state === "string" && STATES.has(state) ? `state-${state}` : "state-other";
}

// "Running for" is shown only while a box runs or is paused.
export function showsRuntime(box) {
  return (box.state === "running" || box.state === "paused") && Number.isFinite(box.started_at);
}

const DONE = {
  "lockdown.on": "Lockdown is on. Every agent is stopped.",
  "box.reorder": "The queue order is saved.",
};

// What the overview says after an action the daemon accepted.
export function doneText(action) {
  return Object.hasOwn(DONE, action) ? DONE[action] : "Done.";
}

// Where a card links to, or null.
export function hrefFor(box) {
  if (box.state === "done") return `#/box/${box.id}`;
  if (box.state === "running" || box.state === "paused") return `#/box/${box.id}/steer`;
  return null;
}

// The full new order of the queued boxes after moving `id` by dir (-1 up,
// +1 down), or null when it cannot move.
export function reorderIds(boxes, id, dir) {
  const ids = boxes.filter((b) => b.state === "queued").map((b) => b.id);
  const i = ids.indexOf(id);
  const j = i + dir;
  if (i < 0 || j < 0 || j >= ids.length) return null;
  [ids[i], ids[j]] = [ids[j], ids[i]];
  return ids;
}

export function byteLength(s) {
  return new TextEncoder().encode(String(s)).length;
}

// "12 / 4096 bytes"; over reports whether the text is too long.
export function counter(s) {
  const n = byteLength(s);
  return { text: `${n} / ${MAX_STEER_BYTES} bytes`, over: n > MAX_STEER_BYTES };
}

// The machine command for a refused action, or null when none is known.
export function machineCommand(action, id) {
  switch (action) {
    case "box.steer": return `saiife box say ${id} "…"`;
    case "box.resume": return `saiife box resume ${id}`;
    case "box.land": return `saiife box land ${id}`;
    default: return null;
  }
}
