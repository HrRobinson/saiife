// The one way to build elements. Strings become text nodes, never markup.
// The document is read lazily so a test can supply a fake one.

const PLAIN = new Set([
  "class", "id", "type", "name", "value", "placeholder", "for", "role",
  "disabled", "rows", "maxlength", "href", "title",
]);
const PREFIXED = /^(aria|data)-[a-z0-9-]+$/;
const EVENT = /^[a-z]+$/;

function doc() {
  return globalThis.document;
}

function allowed(name) {
  return PLAIN.has(name) || PREFIXED.test(name);
}

export function h(tag, attrs = {}, ...children) {
  const d = doc();
  const el = d.createElement(tag);
  for (const [name, value] of Object.entries(attrs || {})) {
    if (name === "on") {
      for (const [ev, fn] of Object.entries(value)) {
        if (!EVENT.test(ev) || typeof fn !== "function") {
          throw new Error(`listener for ${ev} must be a function`);
        }
        el.addEventListener(ev, fn);
      }
      continue;
    }
    if (!allowed(name)) {
      throw new Error(`attribute ${name} is not allowed`);
    }
    if (name === "href" && !(typeof value === "string" && value.startsWith("#/"))) {
      throw new Error("href must start with #/");
    }
    if (value === false || value === null || value === undefined) continue;
    el.setAttribute(name, value === true ? "" : String(value));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === "object" ? c : d.createTextNode(String(c)));
  }
  return el;
}

export function clear(el) {
  el.replaceChildren();
}

export function mount(view) {
  const root = doc().getElementById("view");
  root.replaceChildren(view);
}
