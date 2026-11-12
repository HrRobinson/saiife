import test from "node:test";
import assert from "node:assert/strict";
import { h, clear, mount } from "../js/dom.js";

// A tiny fake document: elements with children, attributes and listeners.
class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.textContent = ""; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { this.listeners[t] = f; }
  append(...kids) { this.children.push(...kids); }
  replaceChildren(...kids) { this.children = kids; }
}
const fakeDoc = {
  createElement: (t) => new Node_(t),
  createTextNode: (s) => ({ text: s }),
  getElementById: (id) => (id === "view" ? view : null),
};
const view = new Node_("main");
globalThis.document = fakeDoc;

test("h makes text nodes from strings", () => {
  const el = h("p", { class: "x" }, "<img src=x onerror=alert(1)>", 3);
  assert.equal(el.tag, "p");
  assert.equal(el.attrs.class, "x");
  assert.deepEqual(el.children, [{ text: "<img src=x onerror=alert(1)>" }, { text: "3" }]);
  assert.equal(el.textContent, "");
});

test("h refuses onclick attribute", () => {
  assert.throws(() => h("button", { onclick: "x()" }), /not allowed/);
  assert.throws(() => h("button", { style: "color:red" }), /not allowed/);
  let hit = 0;
  const b = h("button", { on: { click: () => hit++ } }, "Go");
  b.listeners.click();
  assert.equal(hit, 1);
  assert.throws(() => h("button", { on: { click: "x()" } }), /listener/);
});

test("h refuses javascript href", () => {
  assert.throws(() => h("a", { href: "javascript:alert(1)" }), /href/);
  assert.throws(() => h("a", { href: "https://evil.example/" }), /href/);
  assert.equal(h("a", { href: "#/inbox" }, "Inbox").attrs.href, "#/inbox");
});

test("clear and mount replace the view", () => {
  mount(h("p", {}, "a"));
  assert.equal(view.children.length, 1);
  clear(view);
  assert.equal(view.children.length, 0);
});
