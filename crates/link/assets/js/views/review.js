// Review one done box: its diff and tests, then Approve / Reject / Revise.
// One box.diff answer is shown as is; the renderer caps it at 2000 lines.
import { h } from "../dom.js";
import { visible, short } from "../format.js";
import { ACTIONS, outcome } from "../actions.js";
import { Client } from "../wire.js";
import { parse, render as renderDiff } from "../diff.js";
import { show } from "../touchprompt.js";

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

export function view(client, id) {
  const head = h("div", {}, h("p", { role: "status", "aria-live": "polite" }, "Loading the diff…"));
  const body = h("div", {});
  const out = h("div", { role: "status", "aria-live": "polite" });
  const approve = h("button", { type: "button", class: "primary", disabled: true }, "Approve with touch");
  const reject = h("button", { type: "button", class: "danger" }, "Reject");
  const reviseBtn = h("button", { type: "button", "aria-expanded": "false" }, "Revise");
  const note = h("textarea", { id: "revise-comment", name: "comment", rows: 3 });
  const reviseForm = h(
    "form",
    {},
    h("label", { for: "revise-comment" }, "What should the box change?"),
    note,
    h("p", {}, h("button", { type: "submit", class: "primary" }, "Send for revision")),
  );
  reviseForm.hidden = true;
  let sha = null;
  let left = false;

  const leave = () => {
    left = true;
  };
  window.addEventListener("hashchange", leave, { once: true });

  async function run(action, args, summary, onDone) {
    out.replaceChildren(h("p", { class: "muted" }, "Working…"));
    const a = await client.send(action, args);
    if (left) return;
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
    if (!a.ok) {
      head.replaceChildren(h("p", { class: "error", role: "alert" }, `Could not load the diff. ${message(a)}`));
      return;
    }
    const d = a.result || {};
    sha = typeof d.diff_sha256 === "string" ? d.diff_sha256 : null;
    approve.disabled = sha === null;
    const files = Array.isArray(d.files) ? d.files : [];
    const kids = [
      h("p", {}, `Base commit `, h("code", {}, short(visible(d.base_commit))), " · Diff ", sha === null ? "?" : digest(sha)),
      h("p", {}, `${files.length} files changed`),
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
