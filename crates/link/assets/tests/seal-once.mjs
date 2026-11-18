// The browser end of one hub seal handshake, for crates/link/tests/js_seal_interop.rs.
// Line protocol on stdio, JSON one per line:
//   out 1: {browser_eph, device_pub}
//   in  1: {machine_eph, session_id, machine_sig, machine_pub}
//   out 2: {seal_auth_sig, sealed}   (sealed = "ping from js")
//   in  2: {sealed}                  (from Rust)
//   out 3: {opened}
import { createInterface } from "node:readline";
import { b64u, unb64u, deviceIdOf } from "../js/wire.js";
import * as seal from "../js/seal.js";

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const next = async () => JSON.parse((await lines.next()).value);
const out = (o) => process.stdout.write(JSON.stringify(o) + "\n");

const P256 = { name: "ECDSA", namedCurve: "P-256" };
const dev = await crypto.subtle.generateKey(P256, false, ["sign", "verify"]);
const devPub = new Uint8Array(await crypto.subtle.exportKey("raw", dev.publicKey));
const eph = await seal.newEphemeral();
out({ browser_eph: b64u(eph.publicRaw), device_pub: b64u(devPub) });

const m = await next();
const machineEph = unb64u(m.machine_eph);
const sessionId = unb64u(m.session_id);
const deviceId = await deviceIdOf(devPub);
const ok = await seal.verifyMachineHello(unb64u(m.machine_pub), sessionId, machineEph, { deviceId }, unb64u(m.machine_sig));
if (!ok) throw new Error("machine hello did not verify");
const sig = await seal.handshakeSig(dev.privateKey, sessionId, machineEph, eph.publicRaw);
const ch = await seal.finishBrowser(eph, machineEph, sessionId);
out({ seal_auth_sig: b64u(sig), sealed: b64u(await ch.seal(new TextEncoder().encode("ping from js"))) });

const r = await next();
out({ opened: new TextDecoder().decode(await ch.open(unb64u(r.sealed))) });
