// The panel for an action that needs a touch. It never looks like success.
// Plan 31 adds the "Touch now" button here.
import { h } from "./dom.js";
import { visible } from "./format.js";
import { machineCommand } from "./overviewlogic.js";

const WHAT = {
  "box.steer": "Send a message to the box",
  "box.resume": "Resume the box",
  "box.land": "Land the box's changes",
};

// -> a node to put in the page. `summary` is a short text of what was asked.
export function show(refusal, { action, id, summary } = {}) {
  const code = refusal && typeof refusal.short_code === "string" ? refusal.short_code : null;
  const what = summary || WHAT[action] || String(action);
  return h(
    "section",
    { class: "touchprompt", role: "alert" },
    h("h2", {}, "Not done yet"),
    h("p", {}, `Asked: ${visible(what)}`),
    h("p", {}, `Box: ${visible(id)}`),
    code ? h("p", {}, "Code: ", h("span", { class: "code" }, visible(code))) : null,
    h("p", {}, "Needs a touch on a paired passkey."),
    h("p", { class: "muted" }, "On the machine, run:"),
    h("pre", {}, machineCommand(action, id)),
    refusal && refusal.message ? h("p", { class: "muted" }, visible(refusal.message)) : null,
  );
}
