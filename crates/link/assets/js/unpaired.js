// What every screen does when the daemon no longer knows this browser (rule
// unknown_device, ruling R-F1): forget the key, go to #/pair, and the pair
// screen says so once. No DOM. The pairing wait does not use this: its
// device is held in memory until the owner confirms.
import * as keystore from "./keystore.js";
import { outcome } from "./actions.js";

export const UNPAIRED = "This browser is no longer paired.";
export const PAIR_AGAIN = "To pair it again, run saiife workspace pair --local on the machine and open the link it prints.";

let notice = false;

function goTo(hash) {
  globalThis.location.hash = hash;
}

// -> true when `answer` meant unpaired and was handled; the screen stops.
export async function leaveIfUnpaired(answer, { store = keystore, go = goTo } = {}) {
  if (outcome(answer) !== "unpaired") return false;
  notice = true;
  try {
    await store.forgetDevice();
  } catch {
    // No IndexedDB: nothing to forget; the pair screen still says so.
  }
  go("#/pair");
  return true;
}

// Whether the pair screen should say "no longer paired"; true once.
export function takeNotice() {
  const n = notice;
  notice = false;
  return n;
}
