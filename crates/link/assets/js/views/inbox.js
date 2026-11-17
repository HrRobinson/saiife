// The Approve inbox: what waits for a touch. Nothing approves without this
// browser's passkey (touch.js), and there is no URL that approves (§9.6).
// A box's land is approved on its Review screen, next to its diff; a v2
// approval request is approved here, with a touch for exactly that request.
import { h } from "../dom.js";
import { visible } from "../format.js";
import { ACTIONS } from "../actions.js";
import { Client } from "../wire.js";
import { className, promptAction, timeLeft } from "../inboxlogic.js";
import { show } from "../touchprompt.js";
import { leaveIfUnpaired } from "../unpaired.js";
import { poller } from "../poller.js";
import { touch } from "../touch.js";

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

  function row(p, now) {
    const t = timeLeft(p.expires_at, now);
    const boxId = typeof p.box_id === "string" && BOX_ID.test(p.box_id) ? p.box_id : null;
    const kids = [
      h("h2", {}, visible(className(p.class))),
      h("p", {}, visible(p.summary)),
      boxId ? h("p", {}, "Box: ", h("a", { href: `#/box/${boxId}` }, boxId)) : null,
      h("p", {}, "Code: ", h("span", { class: "code" }, visible(p.short_code))),
      h("p", { class: "muted" }, t.text),
    ];
    if (!t.expired && p.class === "land" && boxId) {
      // The diff is on the Review screen; Approve there asks the touch.
      const review = () => {
        location.hash = `#/box/${boxId}`;
      };
      kids.push(h("p", {}, h("button", { type: "button", class: "primary", on: { click: review } }, "Review and approve")));
    } else if (!t.expired) {
      const open = () =>
        prompt.replaceChildren(
          show(
            { short_code: p.short_code },
            { action: promptAction(p.class), id: boxId ?? "", summary: `${visible(className(p.class))}: ${p.summary}` },
          ),
        );
      kids.push(h("p", {}, h("button", { type: "button", class: "primary", on: { click: open } }, "Open")));
    }
    return h("article", { class: t.expired ? "card expired" : "card" }, ...kids);
  }

  let approving = false;

  // A v2 approval request (approval.list): with a touch class, Approve asks
  // the daemon for a touch bound to that request and this browser's passkey.
  function approvalRow(r) {
    const n = Number.isSafeInteger(r.id) && r.id >= 0 ? r.id : null;
    const cls = typeof r.touch_class === "string" ? r.touch_class : null;
    const what = [r.type, r.service, r.operation].filter((x) => typeof x === "string").join(" ");
    const kids = [
      h("h2", {}, `Request #${n ?? "?"}`, cls ? ` · ${visible(className(cls))}` : ""),
      h("p", {}, visible(what)),
      typeof r.project === "string" ? h("p", { class: "muted" }, `Project: ${visible(r.project)}`) : null,
    ];
    if (n !== null && cls) {
      const approve = async () => {
        if (approving) return;
        approving = true;
        let a;
        try {
          a = await touch(client, {
            action: ACTIONS.approve,
            args: { id: n },
            mount: (node) => prompt.replaceChildren(node),
          });
        } finally {
          approving = false;
        }
        if (stopped || (await leaveIfUnpaired(a))) return;
        if (a.error === "not_approved") return; // the prompt says so
        if (a.ok) {
          prompt.replaceChildren(h("p", { role: "status" }, `Request #${n} approved.`));
          refresh.now();
          return;
        }
        prompt.replaceChildren(h("p", { class: "error", role: "alert" }, visible(a.message || "That did not work.")));
      };
      kids.push(h("p", {}, h("button", { type: "button", class: "primary", on: { click: approve } }, "Approve with touch")));
    } else {
      kids.push(h("p", { class: "muted" }, "Decide this request on the machine."));
    }
    return h("article", { class: "card" }, ...kids);
  }

  async function poll() {
    if (stopped) return;
    const a = await client.send(ACTIONS.inbox, {});
    if (stopped) return;
    if (await leaveIfUnpaired(a)) return;
    if (!a.ok) {
      head.replaceChildren("Could not load the inbox.");
      note.replaceChildren(visible(a.message || "That did not work."));
      return;
    }
    note.replaceChildren();
    const items = Array.isArray(a.result?.items) ? a.result.items : [];
    // v2 approval requests this owner may decide; none when unavailable.
    const r = await client.send(ACTIONS.approvals, {});
    if (stopped) return;
    const reqs = r.ok && Array.isArray(r.result?.items) ? r.result.items.filter((x) => x && typeof x === "object") : [];
    const now = Math.floor(Date.now() / 1000);
    const n = items.length + reqs.length;
    head.replaceChildren(n ? `${n} waiting` : "Nothing waits for you.");
    list.replaceChildren(...items.map((p) => row(p, now)), ...reqs.map(approvalRow));
  }

  const refresh = poller(poll);

  function tick() {
    if (document.visibilityState === "visible") refresh.tick();
  }

  function stop() {
    stopped = true;
    if (timer !== null) clearInterval(timer);
    timer = null;
    window.removeEventListener("hashchange", stop);
    document.removeEventListener("visibilitychange", tick);
  }

  refresh.tick();
  timer = setInterval(tick, POLL_MS);
  document.addEventListener("visibilitychange", tick);
  window.addEventListener("hashchange", stop);
  return root;
}

export function render() {
  return view(new Client());
}
