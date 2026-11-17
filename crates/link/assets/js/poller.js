// One call at a time for a polling screen. No DOM.
// tick(): a timer tick; skipped while a call is in flight.
// now(): a refresh after an action; while a call is in flight it runs once
// more when that call ends, so an older poll never hides the change.
export function poller(fn) {
  let busy = false;
  let again = false;
  async function loop() {
    busy = true;
    try {
      do {
        again = false;
        try {
          await fn();
        } catch {
          // fn shows its own errors; a throw must not stop the polling.
        }
      } while (again);
    } finally {
      busy = false;
    }
  }
  return {
    tick() {
      return busy ? Promise.resolve() : loop();
    },
    now() {
      if (!busy) return loop();
      again = true;
      return Promise.resolve();
    },
    get busy() {
      return busy;
    },
  };
}
