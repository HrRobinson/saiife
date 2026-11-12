import test from "node:test";
import assert from "node:assert/strict";
import { takeFragment, parse } from "../js/app.js";

function fakes(hash) {
  const log = [];
  const loc = { pathname: "/", hash };
  const hist = {
    replaceState(state, title, url) {
      log.push([state, title, url]);
      // What the browser does: the current entry's URL loses its fragment.
      loc.hash = "";
    },
  };
  return { loc, hist, log };
}

test("a pairing fragment leaves the address bar at once", () => {
  const { loc, hist, log } = fakes("#pair=abc");
  // Synchronous: no promise, no await before the address bar is clean.
  const got = takeFragment(loc, hist);
  assert.equal(got, "#pair=abc");
  assert.deepEqual(log, [[null, "", "/"]]);
  assert.equal(loc.hash, "");
  // replaceState, not a new entry: nothing pushed, nothing kept.
  assert.equal(takeFragment(loc, hist), null);
  assert.equal(log.length, 1);
});

test("other hashes are left alone", () => {
  for (const h of ["", "#/pair", "#/overview", "#/box/b-1", "#pairs=x", "#/pair=x"]) {
    const { loc, hist, log } = fakes(h);
    assert.equal(takeFragment(loc, hist), null, h);
    assert.deepEqual(log, []);
    assert.equal(loc.hash, h);
  }
  assert.equal(parse("#pair=abc").name, "overview");
});
