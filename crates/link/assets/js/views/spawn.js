// Start a new box from a template: Start now or Queue.
import { h } from "../dom.js";
import { visible } from "../format.js";
import { ACTIONS, outcome } from "../actions.js";
import { Client } from "../wire.js";
import { taskCounter, checkRepo, checkTask, needsTouchBadge, spawnArgs } from "../inboxlogic.js";
import { show } from "../touchprompt.js";
import { leaveIfUnpaired } from "../unpaired.js";
import { touch } from "../touch.js";

export function view(client) {
  const select = h("select", { id: "spawn-template", name: "template" });
  const info = h("p", { class: "muted", "aria-live": "polite" });
  const repo = h("input", { id: "spawn-repo", name: "repo", type: "text", maxlength: 200 });
  const task = h("textarea", { id: "spawn-task", name: "task", rows: 6 });
  const count = h("p", { class: "muted", "aria-live": "polite" }, taskCounter("").text);
  const out = h("div", { role: "status", "aria-live": "polite" });
  const now = h("button", { type: "button", class: "primary", disabled: true }, "Start now");
  const queue = h("button", { type: "button", disabled: true }, "Queue");
  let templates = [];
  let inFlight = false;

  const buttons = (on) => {
    now.disabled = !on;
    queue.disabled = !on;
  };

  function describe() {
    const t = templates.find((x) => x.name === select.value);
    if (!t) return info.replaceChildren();
    info.replaceChildren(
      visible(t.description),
      needsTouchBadge(t) ? " " : "",
      needsTouchBadge(t) ? h("span", { class: "badge" }, "needs a touch") : "",
    );
  }

  async function load() {
    const a = await client.send(ACTIONS.templates, {});
    if (await leaveIfUnpaired(a)) return;
    if (!a.ok || !Array.isArray(a.result)) {
      out.replaceChildren(h("p", { class: "error", role: "alert" }, visible(a.message || "Could not load the templates.")));
      return;
    }
    templates = a.result;
    select.replaceChildren(...templates.map((t) => h("option", { value: t.name }, visible(t.name))));
    describe();
    buttons(templates.length > 0);
    if (templates.length === 0) out.replaceChildren(h("p", { class: "muted" }, "No templates are set up."));
  }

  async function go(startNow) {
    if (inFlight) return;
    const problem = checkRepo(repo.value) || checkTask(task.value);
    if (problem) return out.replaceChildren(h("p", { class: "error", role: "alert" }, problem));
    inFlight = true;
    buttons(false);
    out.replaceChildren(h("p", { class: "muted" }, "Working…"));
    const args = spawnArgs(select.value, repo.value, task.value, startNow);
    let a;
    try {
      a = await client.send(ACTIONS.spawn, args);
      // A template with secrets or egress: this browser's passkey, with the
      // daemon's summary (shown through visible(): a repo may carry bidi).
      if (outcome(a) === "needs_touch") {
        a = await touch(client, { action: ACTIONS.spawn, args, mount: (n) => out.replaceChildren(n) });
      }
    } finally {
      inFlight = false;
      buttons(templates.length > 0);
    }
    if (await leaveIfUnpaired(a)) return;
    if (a.error === "not_approved") return; // the prompt says "Not approved"
    const o = outcome(a);
    if (o === "done") {
      location.hash = "#/overview";
      return;
    }
    if (o === "needs_touch" || a.rule === "touch_unavailable") {
      return out.replaceChildren(show(a, { action: ACTIONS.spawn, id: "", summary: `Start a box from ${visible(args.template)} for ${visible(args.repo)}` }));
    }
    out.replaceChildren(h("p", { class: "error", role: "alert" }, visible(a.message || "That did not work.")));
  }

  select.addEventListener("change", describe);
  task.addEventListener("input", () => {
    const c = taskCounter(task.value);
    count.replaceChildren(c.text);
    count.className = c.over ? "error" : "muted";
  });
  now.addEventListener("click", () => go(true));
  queue.addEventListener("click", () => go(false));
  load();

  return h(
    "section",
    { class: "spawn" },
    h("h1", {}, "New box"),
    h("form", { on: { submit: (ev) => ev.preventDefault() } },
      h("p", {}, h("label", { for: "spawn-template" }, "Template"), select),
      info,
      h("p", {}, h("label", { for: "spawn-repo" }, "Repo"), repo),
      h("p", {}, h("label", { for: "spawn-task" }, "Task"), task),
      count,
      h("p", {}, now, " ", queue),
    ),
    out,
  );
}

export function render() {
  return view(new Client());
}
