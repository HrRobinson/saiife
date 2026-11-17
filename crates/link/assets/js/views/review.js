// Review one done box: its diff and tests, then Approve / Reject / Revise.
// Approve and Revise ask this browser's passkey (touch.js, plan 31).
// One box.diff answer is shown as is; the renderer caps it at 2000 lines.
import { h } from "../dom.js";
import { visible, short, plural } from "../format.js";
import { ACTIONS, outcome } from "../actions.js";
import { Client } from "../wire.js";
import { parse, render as renderDiff } from "../diff.js";
import { show } from "../touchprompt.js";
import { leaveIfUnpaired } from "../unpaired.js";
import { touch, pendingLand } from "../touch.js";

const message = (a) => visible(a.message || "That did not work.");

function statusOf(f) {
  const s = f.status;
  if (s === "added") return "added";
  if (s === "deleted") return "deleted";
  if (s && typeof s === "object" && s.renamed) return `renamed from ${visible(s.renamed.from)}`;
  return "modified";
}

function fileRow(f) {
  const counts = f.binary ? "binary" : `+${Number(f.added) || 0} −${Number(f.removed) || 0}`;
  return h("li", {}, h("code", {}, visible(f.path)), ` · ${statusOf(f)} · ${counts}`);
}

function testsLine(t) {
  if (!t) return h("p", { class: "muted" }, "No test results.");
  const failed = Number(t.failed) || 0;
  return h(
    "p",
    { class: failed > 0 ? "error" : "" },
    `Tests: ${Number(t.passed) || 0} passed, ${failed} failed, ${Number(t.skipped) || 0} skipped · ${visible(t.summary)}`,
  );
}

// FU1: the box changed files while its in-box guard reported no checks.
// Verbatim saiife_wire::source::GUARD_SKIPPED_WHY (crates/link/tests/assets.rs checks it).
export const GUARD_SKIPPED =
  "the box changed files but its in-box guard reported no checks; the hook may have been disabled (a signal only: the box boundary still applies)";

// A warning badge when the daemon flagged the box; nothing otherwise.
function guardNote(g) {
  if (!g || g.skipped !== true) return null;
  return h(
    "p",
    { class: "banner", role: "note" },
    h("span", { class: "badge", title: GUARD_SKIPPED }, "guard skipped"),
    " ",
    GUARD_SKIPPED.charAt(0).toUpperCase() + GUARD_SKIPPED.slice(1),
  );
}

// The digest, short; a tap shows all of it.
function digest(sha) {
  let open = false;
  const b = h("button", { type: "button", class: "digest", "aria-expanded": "false", "aria-label": "Show the full diff digest" }, short(visible(sha)));
  b.addEventListener("click", () => {
    open = !open;
    b.replaceChildren(open ? visible(sha) : short(visible(sha)));
    b.setAttribute("aria-expanded", String(open));
  });
  return b;
}

// `credentials` is navigator.credentials unless a test hands in a fake.
export function view(client, id, { credentials } = {}) {
  const head = h("div", {}, h("p", { role: "status", "aria-live": "polite" }, "Loading the diff…"));
  const body = h("div", {});
  const out = h("div", { role: "status", "aria-live": "polite" });
  const approve = h("button", { type: "button", class: "primary", disabled: true }, "Approve with touch");
  const reject = h("button", { type: "button", class: "danger", disabled: true }, "Reject");
  const reviseBtn = h("button", { type: "button", "aria-expanded": "false" }, "Revise");
  const note = h("textarea", { id: "revise-comment", name: "comment", rows: 3 });
  const submitRevise = h("button", { type: "submit", class: "primary" }, "Send for revision");
  const reviseForm = h(
    "form",
    {},
    h("label", { for: "revise-comment" }, "What should the box change?"),
    note,
    h("p", {}, submitRevise),
  );
  reviseForm.hidden = true;
  let sha = null;
  let loaded = false; // the diff is on the page (Reject needs it)
  let inFlight = false; // one request at a time
  let left = false;

  // Approve needs the digest, Reject the diff; nothing while a request runs.
  const buttons = () => {
    approve.disabled = inFlight || sha === null;
    reject.disabled = inFlight || !loaded;
    reviseBtn.disabled = inFlight;
    submitRevise.disabled = inFlight;
  };

  const leave = () => {
    left = true;
  };
  window.addEventListener("hashchange", leave, { once: true });

  async function run(action, args, summary, onDone) {
    if (inFlight) return;
    inFlight = true;
    buttons();
    out.replaceChildren(h("p", { class: "muted" }, "Working…"));
    let a;
    const mount = (n) => {
      if (!left) out.replaceChildren(n);
    };
    const opts = credentials ? { credentials } : {};
    try {
      if (action === ACTIONS.land) {
        // A land always needs a touch (no steer window covers it): answer
        // the box's pending land straight away, with no proof-less frame
        // first. None pending, or no passkey here: the machine prompt.
        const p = await pendingLand(client, id);
        if (left) return;
        a = p
          ? await touch(client, { action, args, ...p, mount, ...opts })
          : { ok: false, error: "forbidden", rule: "touch_required", message: "" };
      } else {
        a = await client.send(action, args);
        // Revise asks the daemon for a touch when no steer window is open.
        if (!left && outcome(a) === "needs_touch") a = await touch(client, { action, args, mount, ...opts });
      }
    } finally {
      inFlight = false;
      buttons();
    }
    if (left) return;
    if (await leaveIfUnpaired(a)) return;
    if (a.error === "not_approved") return; // the prompt says "Not approved"
    if (a.rule === "touch_unavailable") return out.replaceChildren(show(a, { action, id, summary }));
    const o = outcome(a);
    // A touch-level action is never shown as done here.
    if (o === "needs_touch") return out.replaceChildren(show(a, { action, id, summary }));
    if (o === "done") return onDone();
    out.replaceChildren(h("p", { class: "error", role: "alert" }, message(a)));
  }

  approve.addEventListener("click", () => {
    if (sha === null) return;
    run(ACTIONS.land, { id, diff_sha256: sha }, "Land the box's changes", () => {
      out.replaceChildren(h("p", {}, "The machine accepted the request."));
    });
  });
  reject.addEventListener("click", () => {
    if (!loaded || inFlight) return;
    if (!window.confirm("Discard this box's work?")) return;
    run(ACTIONS.discard, { id }, "Discard the box's work", () => {
      location.hash = "#/overview";
    });
  });
  reviseBtn.addEventListener("click", () => {
    reviseForm.hidden = !reviseForm.hidden;
    reviseBtn.setAttribute("aria-expanded", String(!reviseForm.hidden));
    if (!reviseForm.hidden) note.focus();
  });
  reviseForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const comment = note.value;
    if (comment.trim() === "") return;
    run(ACTIONS.revise, { id, comment }, "Send the box back with a comment", () => {
      out.replaceChildren(h("p", {}, "The box is working on it."));
    });
  });

  async function load() {
    const a = await client.send(ACTIONS.diff, { id });
    if (left) return;
    if (await leaveIfUnpaired(a)) return;
    if (!a.ok) {
      head.replaceChildren(h("p", { class: "error", role: "alert" }, `Could not load the diff. ${message(a)}`));
      return;
    }
    const d = a.result || {};
    sha = typeof d.diff_sha256 === "string" ? d.diff_sha256 : null;
    const files = Array.isArray(d.files) ? d.files : [];
    const guard = guardNote(d.guard);
    const kids = [
      ...(guard ? [guard] : []),
      h("p", {}, `Base commit `, h("code", {}, short(visible(d.base_commit))), " · Diff ", sha === null ? "?" : digest(sha)),
      h("p", {}, `${plural(files.length, "file")} changed`),
      h("ul", { class: "files" }, files.map(fileRow)),
      testsLine(d.tests),
    ];
    if (d.truncated) {
      kids.push(
        h(
          "p",
          { class: "banner", role: "note" },
          "The diff is larger than 2 MB; review the rest on the machine: ",
          h("code", {}, `saiife box diff ${id}`),
        ),
      );
    }
    head.replaceChildren(...kids);
    const r = renderDiff(parse(d.unified), h, {});
    body.replaceChildren(...r.nodes);
    loaded = true;
    buttons();
  }

  load();
  return h(
    "section",
    { class: "review" },
    h("h1", {}, `Review ${visible(id)}`),
    h("p", {}, h("a", { href: "#/overview" }, "Back to the overview")),
    head,
    body,
    reviseForm,
    out,
    h("div", { class: "actions" }, approve, reject, reviseBtn),
  );
}

export function render(route) {
  return view(new Client(), route.id);
}
