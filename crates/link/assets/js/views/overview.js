// The overview: one card per box, polled every 3 s while the tab is visible.
import { h } from "../dom.js";
import { visible, runtime } from "../format.js";
import { ACTIONS, outcome } from "../actions.js";
import { Client } from "../wire.js";
import { headerLine, preview, hrefFor, reorderIds } from "../overviewlogic.js";

export const POLL_MS = 3000;

function message(a) {
  return visible(a.message || "That did not work.");
}

function taskNode(task) {
  const p = preview(task);
  const text = h("span", {}, visible(p.text));
  if (!p.cut) return h("p", {}, text);
  let open = false;
  const more = h("button", { type: "button", "aria-expanded": "false" }, "Show all");
  more.addEventListener("click", () => {
    open = !open;
    text.replaceChildren(visible(open ? task : p.text));
    more.replaceChildren(open ? "Show less" : "Show all");
    more.setAttribute("aria-expanded", String(open));
  });
  return h("p", {}, text, "… ", more);
}

export function view(client) {
  const head = h("p", { role: "status", "aria-live": "polite" }, "Loading…");
  const note = h("p", { class: "error", role: "alert" });
  const list = h("div", { class: "boxes" });
  const lock = h("button", { type: "button", class: "danger" }, "Lockdown on");
  const root = h("section", { class: "overview" }, h("h1", {}, "Overview"), head, h("p", {}, lock), note, list);
  let last = [];
  let timer = null;
  let stopped = false;
  let busy = false;

  const say = (a) => note.replaceChildren(a.ok ? "" : message(a));

  async function act(action, args) {
    const a = await client.send(action, args);
    say(a);
    if (outcome(a) === "done") await poll();
  }

  function card(b, now) {
    const href = hrefFor(b);
    const title = h("h2", {}, href ? h("a", { href }, visible(b.id)) : visible(b.id));
    const kids = [
      title,
      h("p", {}, h("span", { class: `badge state-${b.state}` }, b.state)),
      taskNode(b.task),
      h("p", { class: "muted" }, `${visible(b.template)} · ${visible(b.repo)}`),
    ];
    if (b.started_at !== null && b.started_at !== undefined) {
      kids.push(h("p", { class: "muted" }, `Running for ${runtime(b.started_at, now)}`));
    }
    if (b.state === "queued") {
      const move = (dir, label) => {
        const ids = reorderIds(last, b.id, dir);
        return h(
          "button",
          { type: "button", disabled: ids === null, "aria-label": `${label} ${b.id}`, on: { click: () => act(ACTIONS.reorder, { ids: reorderIds(last, b.id, dir) }) } },
          dir < 0 ? "↑" : "↓",
        );
      };
      kids.push(h("p", {}, move(-1, "Move up"), " ", move(1, "Move down")));
    }
    return h("article", { class: "card" }, ...kids);
  }

  async function poll() {
    if (stopped || busy) return;
    busy = true;
    const a = await client.send(ACTIONS.overview, {});
    busy = false;
    if (stopped) return;
    if (!a.ok) {
      head.replaceChildren("Could not load the boxes.");
      say(a);
      return;
    }
    say({ ok: true });
    const ov = a.result;
    last = Array.isArray(ov.boxes) ? ov.boxes : [];
    head.replaceChildren(headerLine(ov));
    const now = Math.floor(Date.now() / 1000);
    list.replaceChildren(...(last.length ? last.map((b) => card(b, now)) : [h("p", { class: "muted" }, "No boxes yet.")]));
  }

  function tick() {
    if (document.visibilityState === "visible") poll();
  }

  function stop() {
    stopped = true;
    if (timer !== null) clearInterval(timer);
    timer = null;
    window.removeEventListener("hashchange", stop);
    document.removeEventListener("visibilitychange", tick);
  }

  lock.addEventListener("click", () => {
    if (window.confirm("Stop every agent on this machine?")) act(ACTIONS.lockdownOn, {});
  });
  poll();
  timer = setInterval(tick, POLL_MS);
  // Coming back to the tab refreshes at once.
  document.addEventListener("visibilitychange", tick);
  window.addEventListener("hashchange", stop);
  return root;
}

export function render() {
  return view(new Client());
}
