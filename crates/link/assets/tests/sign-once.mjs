// Prints one browser-signed frame as JSON {public_raw, body, sig} (b64u) for
// crates/link/tests/js_interop.rs to verify in Rust.
import { b64u, deviceIdOf, buildBody, sign } from "../js/wire.js";

const P256 = { name: "ECDSA", namedCurve: "P-256" };
const pair = await crypto.subtle.generateKey(P256, false, ["sign", "verify"]);
const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
const body = buildBody({
  machineId: "0123456789abcdef0123456789abcdef",
  epoch: "AwMDAwMDAwMDAwMDAwMDAw",
  deviceId: await deviceIdOf(publicRaw),
  action: "box.stop",
  args: { id: "b-1", note: "café ‮" },
  now: Math.floor(Date.now() / 1000),
});
const sig = await sign(pair.privateKey, body);
process.stdout.write(JSON.stringify({ public_raw: b64u(publicRaw), body, sig }) + "\n");
