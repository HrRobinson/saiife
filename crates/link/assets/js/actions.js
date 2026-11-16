// The one list of what each button sends; views import it. No DOM.

export const ACTIONS = Object.freeze({
  overview: "box.overview",
  diff: "box.diff",
  stop: "box.stop",
  pause: "box.pause",
  discard: "box.discard",
  reorder: "box.reorder",
  steer: "box.steer",
  revise: "box.revise",
  land: "box.land",
  resume: "box.resume",
  inbox: "box.inbox",
  templates: "box.templates",
  spawn: "box.spawn",
  whoami: "workspace.whoami",
  termRead: "box.term.read",
  approvals: "approval.list",
  approve: "approval.approve",
  lockdownOn: "lockdown.on",
});

const BY_RULE = {
  touch_required: "needs_touch",
  unknown_device: "unpaired",
  device_pending: "pending",
  busy: "retry",
  unreachable: "retry",
};

// What the page does with an answer (keyed on `rule ?? error`, ruling R-1).
export function outcome(answer) {
  if (!answer || typeof answer !== "object") return "refused";
  if (answer.ok === true) return "done";
  const key = answer.rule ?? answer.error;
  return (typeof key === "string" && Object.hasOwn(BY_RULE, key)) ? BY_RULE[key] : "refused";
}
