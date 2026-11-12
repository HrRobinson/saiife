// A small unified-diff parser (no DOM) and a renderer that builds text
// nodes only, through the h() it is given. Every path and line is hostile:
// the renderer passes them through visible(), never resolves a path and
// never makes a link.
import { visible, plural } from "./format.js";

export const MAX_LINES = 2000;

const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

// "a/x" -> "x"; "/dev/null" -> null. A trailing tab (git's marker for names
// with spaces in plain diffs) is dropped.
function side(s, prefix) {
  const p = s.endsWith("\t") ? s.slice(0, -1) : s;
  if (p === "/dev/null") return null;
  return p.startsWith(prefix) ? p.slice(prefix.length) : p;
}

// "a/X b/Y" from a "diff --git" line. Equal names (the common case) split
// exactly even when they hold " b/"; otherwise at the last " b/".
function gitPaths(rest) {
  if (rest.startsWith("a/")) {
    // "a/" + x + " b/" + x: n = 5 + 2 * len(x).
    const n = rest.length;
    if ((n - 5) % 2 === 0) {
      const half = (n - 5) / 2;
      const x = rest.slice(2, 2 + half);
      if (rest.slice(2 + half, 5 + half) === " b/" && rest.slice(5 + half) === x) return [x, x];
    }
    const i = rest.lastIndexOf(" b/");
    if (i > 0) return [rest.slice(2, i), rest.slice(i + 3)];
  }
  return [rest, rest];
}

function newFile(oldPath, newPath) {
  return { oldPath, newPath, binary: false, hunks: [] };
}

// -> [{oldPath, newPath, binary, hunks: [{header, lines: [{kind, text, oldNo, newNo}]}]}]
export function parse(unified) {
  const src = String(unified ?? "");
  const rows = src.split("\n");
  if (rows.length && rows[rows.length - 1] === "") rows.pop();
  const files = [];
  let file = null;
  let hunk = null; // the open hunk
  let left = null; // {o, n}: lines still owed by a counted hunk; null if uncounted
  let o = 0;
  let n = 0;

  const close = () => {
    hunk = null;
    left = null;
  };
  const push = (kind, text) => {
    const l = { kind, text, oldNo: null, newNo: null };
    if (kind === " " || kind === "-") l.oldNo = left ? o++ : null;
    if (kind === " " || kind === "+") l.newNo = left ? n++ : null;
    if (left) {
      if (kind !== "+" && kind !== "\\") left.o--;
      if (kind !== "-" && kind !== "\\") left.n--;
    }
    hunk.lines.push(l);
  };

  for (const row of rows) {
    if (hunk) {
      const c = row[0];
      if (left && (left.o > 0 || left.n > 0)) {
        // A counted hunk owes lines: anything the counts allow is content.
        if (c === "+" && left.n > 0) { push("+", row.slice(1)); continue; }
        if (c === "-" && left.o > 0) { push("-", row.slice(1)); continue; }
        if (c === " " && left.o > 0 && left.n > 0) { push(" ", row.slice(1)); continue; }
        if (row === "" && left.o > 0 && left.n > 0) { push(" ", ""); continue; }
        if (c === "\\") { push("\\", row.slice(1)); continue; }
      } else if (c === "\\") {
        push("\\", row.slice(1));
        continue;
      } else if (!left && (c === "+" || c === " " || (c === "-" && !row.startsWith("--- ")))) {
        // An uncounted hunk runs until a header: "diff --git", "--- " or "@@".
        push(c, row.slice(1));
        continue;
      }
      close();
    }

    if (row.startsWith("diff --git ")) {
      const [a, b] = gitPaths(row.slice(11));
      file = newFile(a, b);
      files.push(file);
      continue;
    }
    const m = HUNK.exec(row);
    if (m && file) {
      o = Number(m[1]);
      n = Number(m[3]);
      left = { o: m[2] === undefined ? 1 : Number(m[2]), n: m[4] === undefined ? 1 : Number(m[4]) };
      hunk = { header: row, lines: [] };
      file.hunks.push(hunk);
      continue;
    }
    if (row.startsWith("--- ")) {
      // A plain unified diff (no "diff --git") starts a file here.
      if (!file || file.hunks.length > 0 || file.sawMinus) {
        file = newFile(null, null);
        files.push(file);
      }
      file.oldPath = side(row.slice(4), "a/");
      file.sawMinus = true;
      continue;
    }
    if (row.startsWith("+++ ") && file) {
      file.newPath = side(row.slice(4), "b/");
      file.sawPlus = true;
      continue;
    }
    if (!file) continue;
    if (row.startsWith("rename from ")) { file.oldPath = row.slice(12); continue; }
    if (row.startsWith("rename to ")) { file.newPath = row.slice(10); continue; }
    if (row.startsWith("Binary files ") || row === "GIT binary patch") { file.binary = true; continue; }
    // Lines after "+++" with no "@@" (a cut or hand-made diff): shown, unnumbered.
    if (file.sawPlus && (row[0] === "+" || row[0] === "-" || row[0] === " ")) {
      hunk = { header: null, lines: [] };
      left = null;
      file.hunks.push(hunk);
      push(row[0], row.slice(1));
    }
    // Any other header line (index, mode, similarity) is not shown.
  }
  for (const f of files) {
    delete f.sawMinus;
    delete f.sawPlus;
  }
  return files;
}

const CLASS = { "+": "add", "-": "del", " ": "ctx", "\\": "note" };

function num(x) {
  return x === null ? "     " : String(x).padStart(5);
}

function title(f) {
  const a = f.oldPath;
  const b = f.newPath;
  if (a === null && b === null) return "(no name)";
  if (a === null) return `${visible(b)} (new)`;
  if (b === null) return `${visible(a)} (deleted)`;
  if (a !== b) return `${visible(a)} → ${visible(b)}`;
  return visible(b);
}

// -> {nodes, shownLines, hiddenLines}. Builds every node once; at most
// maxLines diff lines become nodes, the rest are counted and said. A file
// cut by the cap says how many of its lines are not shown; a file past the
// cap is its heading and that note only (bounded work on a 2 MB diff).
export function render(files, h, { maxLines = MAX_LINES } = {}) {
  const nodes = [];
  let shown = 0;
  let hidden = 0;
  for (const f of files) {
    const kids = [h("h3", { class: "path" }, title(f))];
    if (f.binary) kids.push(h("p", { class: "muted" }, "binary"));
    let cut = 0;
    for (const hk of f.hunks) {
      const take = Math.min(Math.max(0, maxLines - shown), hk.lines.length);
      cut += hk.lines.length - take;
      if (take === 0) continue;
      const rows = [];
      if (hk.header !== null) rows.push(h("span", { class: "hh" }, visible(hk.header) + "\n"));
      for (let i = 0; i < take; i++) {
        const l = hk.lines[i];
        rows.push(h("span", { class: CLASS[l.kind] }, `${num(l.oldNo)} ${num(l.newNo)} ${l.kind}${visible(l.text)}\n`));
      }
      shown += take;
      kids.push(h("div", { class: "hunk" }, h("pre", {}, rows)));
    }
    if (cut > 0) kids.push(h("p", { class: "muted" }, `${plural(cut, "line")} not shown.`));
    hidden += cut;
    nodes.push(h("section", { class: "diff" }, kids));
  }
  if (hidden > 0) {
    const what = hidden === 1 ? "1 more line is" : `${hidden} more lines are`;
    nodes.push(h("p", { class: "muted" }, `${what} not shown here.`));
  }
  return { nodes, shownLines: shown, hiddenLines: hidden };
}
