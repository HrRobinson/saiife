// Hash router. An unpaired browser always lands on #/pair.
import { mount, h } from "./dom.js";
import { render as overview } from "./views/placeholder.js";
import { render as review } from "./views/placeholder.js";
import { render as steer } from "./views/placeholder.js";
import { render as inbox } from "./views/placeholder.js";
import { render as spawn } from "./views/placeholder.js";
import { render as pair } from "./views/placeholder.js";

const BOX_ID = /^[a-z0-9][a-z0-9-]{0,39}$/;

// Reads the device record from IndexedDB; any error or absence means unpaired.
export function paired() {
  return new Promise((resolve) => {
    try {
      const open = indexedDB.open("saiife-workspace");
      open.onerror = () => resolve(false);
      open.onsuccess = () => {
        try {
          const db = open.result;
          if (!db.objectStoreNames.contains("keys")) {
            db.close();
            return resolve(false);
          }
          const get = db.transaction("keys", "readonly").objectStore("keys").get("device");
          get.onsuccess = () => {
            db.close();
            resolve(get.result !== undefined && get.result !== null);
          };
          get.onerror = () => {
            db.close();
            resolve(false);
          };
        } catch {
          resolve(false);
        }
      };
    } catch {
      resolve(false);
    }
  });
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

async function route() {
  let r = parse(location.hash);
  if (r.name !== "pair" && !(await paired())) {
    location.hash = "#/pair";
    r = parse("#/pair");
  }
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
