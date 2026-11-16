// Pure text helpers. No DOM.
import { isUnsafe } from "./unsafe.js";

// Show the characters the shared sanitizer refuses (`is_unsafe_char` in
// crates/wire/src/text.rs: controls, bidi, zero-width, private use and the
// rest of unsafe.js) as visible escapes. Tab and newline stay as they are.
export function visible(s) {
  if (s === null || s === undefined) return "";
  let out = "";
  for (const ch of String(s)) {
    const c = ch.codePointAt(0);
    if (c === 0x09 || c === 0x0a) out += ch;
    else if (c === 0x1b) out += "⟨ESC⟩";
    else if (isUnsafe(c)) {
      out += "⟨U+" + c.toString(16).toUpperCase().padStart(4, "0") + "⟩";
    } else out += ch;
  }
  return out;
}

export function ago(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h`;
  return `${Math.floor(s / 86400)} d`;
}

export function runtime(started, now) {
  return ago(now - started);
}

export function short(hex, n = 8) {
  return String(hex).slice(0, n);
}

export function bytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1048576).toFixed(1)} MiB`;
  return `${(n / 1073741824).toFixed(1)} GiB`;
}

// "1 file", "2 files".
export function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}
