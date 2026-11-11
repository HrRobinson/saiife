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

// What the machine command is for a refused action.
export function machineCommand(action, id) {
  switch (action) {
    case "box.steer": return `saiife box say ${id} "…"`;
    case "box.resume": return `saiife box resume ${id}`;
    case "box.land": return `saiife box land ${id}`;
    default: return `saiife box ${String(action).replace(/^box\./, "")} ${id}`;
  }
}
