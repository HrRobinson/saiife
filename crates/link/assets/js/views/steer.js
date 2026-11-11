// Steer one box: a message, Pause, Resume, Stop. Plan 31 adds the terminal.
import { h } from "../dom.js";
import { visible } from "../format.js";
import { ACTIONS, outcome } from "../actions.js";
import { Client } from "../wire.js";
import { counter } from "../overviewlogic.js";
import { show } from "../touchprompt.js";

export function view(client, id) {
  const input = h("textarea", { id: "steer-msg", name: "msg", rows: 4 });
  const count = h("p", { class: "muted", "aria-live": "polite" }, counter("").text);
  const out = h("div", { role: "status", "aria-live": "polite" });
  const send = h("button", { type: "submit", class: "primary" }, "Send message");

  async function run(action, args, summary, okText) {
    out.replaceChildren(h("p", { class: "muted" }, "Working…"));
    const a = await client.send(action, args);
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
  );
}

export function render(route) {
  return view(new Client(), route.id);
}
