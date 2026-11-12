// The Approve inbox: what waits for a touch. A row only opens the touch
// prompt; nothing here approves, and there is no URL that approves (§9.6).
import { h } from "../dom.js";
import { visible } from "../format.js";
import { ACTIONS } from "../actions.js";
import { Client } from "../wire.js";
import { className, timeLeft } from "../inboxlogic.js";
import { show } from "../touchprompt.js";

export const POLL_MS = 5000;
const BOX_ID = /^[a-z0-9][a-z0-9-]{0,39}$/;

export function view(client) {
  const head = h("p", { role: "status", "aria-live": "polite" }, "Loading…");
  const note = h("p", { class: "error", role: "alert" });
  const list = h("div", { class: "inbox" });
  const prompt = h("div", { "aria-live": "polite" });
  const root = h("section", { class: "inbox-screen" }, h("h1", {}, "Approve"), head, note, list, prompt);
  let timer = null;
  let stopped = false;
  let busy = false;

  function row(p, now) {
    const t = timeLeft(p.expires_at, now);
    const boxId = typeof p.box_id === "string" && BOX_ID.test(p.box_id) ? p.box_id : null;
    const kids = [
      h("h2", {}, className(p.class)),
      h("p", {}, visible(p.summary)),
      boxId ? h("p", {}, "Box: ", h("a", { href: `#/box/${boxId}` }, boxId)) : null,
      h("p", {}, "Code: ", h("span", { class: "code" }, visible(p.short_code))),
      h("p", { class: "muted" }, t.text),
    ];
    if (!t.expired) {
      const open = () =>
        prompt.replaceChildren(
          show(
            { short_code: p.short_code },
            { action: `box.${p.class}`, id: boxId ?? "", summary: `${className(p.class)}: ${p.summary}` },
          ),
        );
      kids.push(h("p", {}, h("button", { type: "button", class: "primary", on: { click: open } }, "Open")));
    }
    return h("article", { class: t.expired ? "card expired" : "card" }, ...kids);
  }

  async function poll() {
    if (stopped || busy) return;
    busy = true;
    const a = await client.send(ACTIONS.inbox, {});
    busy = false;
    if (stopped) return;
    if (!a.ok) {
      head.replaceChildren("Could not load the inbox.");
      note.replaceChildren(visible(a.message || "That did not work."));
      return;
    }
    note.replaceChildren();
    const items = Array.isArray(a.result?.items) ? a.result.items : [];
    const now = Math.floor(Date.now() / 1000);
    head.replaceChildren(items.length ? `${items.length} waiting` : "Nothing waits for you.");
    list.replaceChildren(...items.map((p) => row(p, now)));
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

  poll();
  timer = setInterval(tick, POLL_MS);
  document.addEventListener("visibilitychange", tick);
  window.addEventListener("hashchange", stop);
  return root;
}

export function render() {
  return view(new Client());
}
