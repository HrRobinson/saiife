// The panels for an action that needs a touch. They never look like success.
// `show`: the machine route (no passkey here, or no touch to answer).
// `touchNow` / `notApproved`: the browser's own touch (plan 31, touch.js);
// the short code is on the page before the passkey dialog opens (§8.3).
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
  const cmd = id ? machineCommand(action, id) : null;
  return h(
    "section",
    { class: "touchprompt", role: "alert" },
    h("h2", {}, "Not done yet"),
    h("p", {}, `Asked: ${visible(what)}`),
    id ? h("p", {}, `Box: ${visible(id)}`) : null,
    code ? h("p", {}, "Code: ", h("span", { class: "code" }, visible(code))) : null,
    h("p", {}, "Needs a touch on a paired passkey."),
    cmd ? h("p", { class: "muted" }, "On the machine, run:") : h("p", { class: "muted" }, "Approve it on the machine."),
    cmd ? h("pre", {}, cmd) : null,
    refusal && refusal.message ? h("p", { class: "muted" }, visible(refusal.message)) : null,
  );
}

export const UV = "Needs Face ID, fingerprint or PIN.";

// The touch prompt while the passkey dialog is open. `summary` and the
// short code come from the daemon's touch request.
export function touchNow({ action, id, summary, short_code } = {}) {
  const what = summary || WHAT[action] || String(action);
  return h(
    "section",
    { class: "touchprompt", role: "alert" },
    h("h2", {}, "Touch now"),
    h("p", {}, `Asked: ${visible(what)}`),
    id ? h("p", {}, `Box: ${visible(id)}`) : null,
    h("p", {}, "Code: ", h("span", { class: "code" }, visible(short_code))),
    h("p", {}, "Check that the code is the one you expect, then confirm with your passkey."),
    h("p", { class: "muted" }, UV),
  );
}

// A touch that was cancelled, timed out, failed or used another passkey.
export function notApproved({ action, id, summary } = {}) {
  const what = summary || WHAT[action] || String(action);
  return h(
    "section",
    { class: "touchprompt", role: "alert" },
    h("h2", {}, "Not approved"),
    h("p", {}, `Asked: ${visible(what)}`),
    id ? h("p", {}, `Box: ${visible(id)}`) : null,
    h("p", {}, "Nothing was sent. The touch was cancelled, timed out or did not verify."),
    h("p", { class: "muted" }, UV),
  );
}
