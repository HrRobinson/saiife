// Hash router. An unpaired browser always lands on #/pair.
import { mount, h } from "./dom.js";
import { loadDevice } from "./keystore.js";
import { render as overview } from "./views/overview.js";
import { render as review } from "./views/review.js";
import { render as steer } from "./views/steer.js";
import { render as inbox } from "./views/inbox.js";
import { render as spawn } from "./views/spawn.js";
import { render as pair } from "./views/pair.js";

const BOX_ID = /^[a-z0-9][a-z0-9-]{0,39}$/;

// Unpaired unless the keystore holds a device record (loadDevice never throws).
export async function paired() {
  return (await loadDevice()) !== null;
}

// Maps a hash to a route; unknown hashes and bad box ids become the overview.
export function parse(hash) {
  const parts = String(hash || "").replace(/^#\/?/, "").split("/");
  const [head, id, sub] = parts;
  if (head === "" || head === "overview") return { name: "overview", render: overview };
  if (head === "inbox" && parts.length === 1) return { name: "inbox", render: inbox };
  if (head === "spawn" && parts.length === 1) return { name: "spawn", render: spawn };
  if (head === "pair" && parts.length === 1) return { name: "pair", render: pair };
  if (head === "box" && id !== undefined && BOX_ID.test(id)) {
    if (parts.length === 2) return { name: "review", id, render: review };
    if (parts.length === 3 && sub === "steer") return { name: "steer", id, render: steer };
  }
  return { name: "overview", render: overview };
}

let latest = 0;

// A pairing link "#pair=<offer>": the secret leaves the address bar and
// this history entry at once (replaceState fires no hashchange), before any
// await; the pair view gets it in memory. -> the hash | null.
export function takeFragment(loc = globalThis.location, hist = globalThis.history) {
  const hash = String(loc.hash || "");
  if (!hash.startsWith("#pair=")) return null;
  hist.replaceState(null, "", loc.pathname);
  return hash;
}

async function route() {
  const mine = ++latest;
  const fragment = takeFragment();
  const r = fragment !== null ? { name: "pair", fragment, render: pair } : parse(location.hash);
  if (r.name !== "pair" && !(await paired())) {
    // The hashchange this triggers renders the pair screen.
    if (mine === latest) location.hash = "#/pair";
    return;
  }
  if (mine !== latest) return;
  try {
    mount(r.render(r));
  } catch {
    mount(h("p", {}, "This page could not be shown."));
  }
}

if (typeof window !== "undefined") {
  window.addEventListener("hashchange", route);
  route();
}
