// The js the fakes use, and the one fakes file a vendoring site replaces:
// fakerelay.mjs and fakemachine.mjs import only from here, so they can be
// vendored byte for byte and this file points at the vendored js instead.
export { b64u, unb64u, deviceIdOf } from "../../js/wire.js";
export { machineHelloMsg, keysFromShared, HANDSHAKE_DOMAIN, MACHINE_HELLO_DOMAIN } from "../../js/seal.js";
