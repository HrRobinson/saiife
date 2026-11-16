// Steer one box: a message, Pause, Resume, Stop, and the box's terminal,
// read only (plan 31). Steer and Resume need a touch unless a steer window
// for this box is open; the touch is asked here (touch.js).
import { h } from "../dom.js";
import { visible } from "../format.js";
import { ACTIONS, outcome } from "../actions.js";
import { Client } from "../wire.js";
import { counter } from "../overviewlogic.js";
import { show } from "../touchprompt.js";
import { leaveIfUnpaired } from "../unpaired.js";
import { touch } from "../touch.js";
import { poller, render as renderTerm, ENDED } from "../term.js";

// The pane: one <pre> of text, no controls. Polled while the page is
// visible, at most once per second; stops when the box's terminal ended
// and when the page leaves this screen.
function terminal(client, id) {
  const pre = h("div", {}, renderTerm(null, h));
  const note = h("p", { class: "muted", role: "status", "aria-live": "polite" }, "Loading the terminal…");
  const p = poller({
    client,
    id,
    isVisible: () => document.visibilityState === "visible",
    onUpdate: async ({ screen, ended, error }) => {
      if (error) {
        if (await leaveIfUnpaired(error)) return p.stop();
        note.replaceChildren(visible(error.message || "Could not read the terminal."));
        return;
      }
      pre.replaceChildren(renderTerm(screen, h));
      note.replaceChildren(ended ? ENDED : "Read only. Updated every second.");
    },
  });
  p.start();
  window.addEventListener("hashchange", () => p.stop(), { once: true });
  return h("section", { class: "terminal" }, h("h2", {}, "Terminal"), pre, note);
}

export function view(client, id) {
  const input = h("textarea", { id: "steer-msg", name: "msg", rows: 4 });
  const count = h("p", { class: "muted", "aria-live": "polite" }, counter("").text);
  const out = h("div", { role: "status", "aria-live": "polite" });
  const send = h("button", { type: "submit", class: "primary" }, "Send message");

  async function run(action, args, summary, okText) {
    out.replaceChildren(h("p", { class: "muted" }, "Working…"));
    let a = await client.send(action, args);
    if (await leaveIfUnpaired(a)) return;
    if (outcome(a) === "needs_touch") {
      // No open steer window: ask this browser's passkey.
      a = await touch(client, { action, args, mount: (n) => out.replaceChildren(n) });
      if (await leaveIfUnpaired(a)) return;
      if (a.error === "not_approved") return; // the prompt says "Not approved"
      if (a.rule === "touch_unavailable") return out.replaceChildren(show(a, { action, id, summary }));
    }
    const o = outcome(a);
    if (o === "needs_touch") return out.replaceChildren(show(a, { action, id, summary }));
    if (o === "done") return out.replaceChildren(h("p", {}, okText));
    out.replaceChildren(h("p", { class: "error", role: "alert" }, visible(a.message || "That did not work.")));
  }

  input.addEventListener("input", () => {
    const c = counter(input.value);
    count.replaceChildren(c.text);
    count.className = c.over ? "error" : "muted";
    send.disabled = c.over;
  });
  const submit = (ev) => {
    ev.preventDefault();
    const msg = input.value;
    if (msg === "" || counter(msg).over) return;
    run(ACTIONS.steer, { id, msg }, "Send a message to the box", "Message sent.");
  };
  const simple = (label, action, okText, cls, ask) =>
    h("button", {
      type: "button",
      class: cls,
      on: {
        click: () => {
          if (ask && !window.confirm(ask)) return;
          run(action, { id }, label, okText);
        },
      },
    }, label);

  return h(
    "section",
    { class: "steer" },
    h("h1", {}, `Steer ${visible(id)}`),
    h("p", {}, h("a", { href: "#/overview" }, "Back to the overview")),
    h("form", { on: { submit } }, h("label", { for: "steer-msg" }, "Message to the box"), input, count, h("p", {}, send)),
    h(
      "div",
      { class: "actions" },
      simple("Pause box", ACTIONS.pause, "Box paused.", ""),
      simple("Resume box", ACTIONS.resume, "Box resumed.", ""),
      simple("Stop box", ACTIONS.stop, "Box stopped.", "danger", "Stop this box?"),
    ),
    out,
    terminal(client, id),
  );
}

export function render(route) {
  return view(new Client(), route.id);
}
