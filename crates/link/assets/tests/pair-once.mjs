// Runs pairing.js `pair()` against a real localhost link, for
// crates/link/tests/ui_flows.rs. Args: <base url> <"#pair=..." hash>.
// Prints {deviceId, shortCode, devicePub, replaced} or {error, rule}.
import { pair } from "../js/pairing.js";
import { b64u } from "../js/wire.js";
import { memoryStore } from "../js/keystore.js";

const [base, hash] = process.argv.slice(2);
const store = memoryStore();
let replaced = null;
const history = {
  replaceState(_state, _title, url) {
    replaced = url;
  },
};
// The page's fetch is same-origin; a browser adds Origin to every POST.
const fetch = (url, init = {}) =>
  globalThis.fetch(base + url, { ...init, headers: { ...(init.headers ?? {}), Origin: base } });
const r = await pair({ hash, location: { pathname: "/", hash }, history, fetch, store, label: "Browser on this machine" });
// pair() saves nothing (ruling R-T3c); the device comes back in memory.
const { device, ...rest } = r;
process.stdout.write(
  JSON.stringify({ ...rest, devicePub: device ? b64u(device.publicRaw) : null, saved: (await store.loadDevice()) !== null, replaced }) + "\n",
);
