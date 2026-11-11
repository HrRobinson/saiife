// The pair screen: a label, "Pair this browser", then the short code to
// compare with the machine's while whoami is polled. The router hands over
// the "#pair=" fragment in `route.fragment` after clearing it from the
// address bar; it lives only in this closure.
import { h } from "../dom.js";
import { visible } from "../format.js";
import { Client } from "../wire.js";
import * as keystore from "../keystore.js";
import { pair, watchConfirm, checkLabel, DEFAULT_LABEL, MAX_LABEL_CHARS, WAIT_MS } from "../pairing.js";

const HOW = "On the machine, run saiife workspace pair --local and open the link it prints.";

function show(root, ...kids) {
  root.replaceChildren(...kids);
}

function intro(root) {
  show(root, h("h1", {}, "Pair this browser"), h("p", {}, HOW));
}

function form(root, fragment) {
  const input = h("input", { id: "pair-label", name: "label", type: "text", maxlength: MAX_LABEL_CHARS, value: DEFAULT_LABEL });
  const status = h("p", { role: "status", "aria-live": "polite" });
  const button = h("button", { type: "submit", class: "primary" }, "Pair this browser");
  const submit = async (ev) => {
    ev.preventDefault();
    const label = input.value;
    const why = checkLabel(label);
    if (why) {
      status.className = "error";
      status.replaceChildren(why);
      return;
    }
    button.disabled = true;
    status.className = "muted";
    status.replaceChildren("Pairing…");
    const r = await pair({ hash: fragment, location, history, fetch: (u, i) => fetch(u, i), store: keystore, label });
    if (r.error) {
      button.disabled = false;
      status.className = "error";
      status.replaceChildren(visible(r.error));
      return;
    }
    waiting(root, r.shortCode);
  };
  show(
    root,
    h("h1", {}, "Pair this browser"),
    h(
      "form",
      { on: { submit } },
      h("label", { for: "pair-label" }, "Name for this browser (1 to 40 characters)"),
      input,
      h("p", {}, button),
      status,
    ),
  );
}

function waiting(root, code) {
  const status = h("p", { class: "muted", role: "status", "aria-live": "polite" }, "Waiting for the machine…");
  show(
    root,
    h("h1", {}, "Confirm on the machine"),
    h("p", { class: "code", "aria-label": `Short code ${code}` }, visible(code)),
    h("p", {}, "Check that your machine shows the same code, then confirm there."),
    status,
  );
  const stop = watchConfirm({
    client: new Client(),
    deadline: Date.now() + WAIT_MS,
    onEnd: async (e) => {
      window.removeEventListener("hashchange", stop);
      if (e.kind === "done") {
        location.hash = "#/overview";
        return;
      }
      status.className = "error";
      if (e.kind === "timeout") {
        // Never confirmed (or rejected): this key will never be let in.
        try {
          await keystore.forgetDevice();
        } catch {
          // Nothing kept is still nothing usable.
        }
        status.replaceChildren(`The machine did not confirm this browser. ${HOW}`);
      } else {
        status.replaceChildren(visible(e.message));
      }
    },
  });
  // Leaving the screen ends the polling.
  window.addEventListener("hashchange", stop, { once: true });
}

export function render(route) {
  const root = h("section", { class: "pair" });
  intro(root);
  keystore.loadDevice().then((dev) => {
    if (!route.fragment) {
      if (dev) show(root, h("h1", {}, "This browser is paired"), h("p", {}, h("a", { href: "#/overview" }, "Go to the overview")));
      return;
    }
    if (!dev) return form(root, route.fragment);
    const replace = h("button", { type: "button", class: "danger", on: { click: () => form(root, route.fragment) } }, "Replace this browser's pairing");
    show(
      root,
      h("h1", {}, "This browser is already paired"),
      h("p", {}, "Pairing again replaces the key this browser uses. The old pairing stays on the machine until you revoke it there."),
      h("p", {}, replace, " ", h("a", { href: "#/overview" }, "Keep the current pairing")),
    );
  });
  return root;
}
