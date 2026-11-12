import test from "node:test";
import assert from "node:assert/strict";
import { h } from "../js/dom.js";
import { parse, render } from "../js/diff.js";

// A tiny fake document (as in dom.test.mjs): text nodes are plain objects.
class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { this.listeners[t] = f; }
  append(...kids) { this.children.push(...kids); }
  replaceChildren(...kids) { this.children = kids; }
}
globalThis.document = {
  createElement: (t) => new Node_(t),
  createTextNode: (s) => ({ text: s }),
};

function walk(n, f) {
  f(n);
  for (const c of n.children || []) walk(c, f);
}
function texts(nodes) {
  const out = [];
  for (const n of nodes) walk(n, (x) => { if ("text" in x) out.push(x.text); });
  return out;
}
function tags(nodes) {
  const out = new Set();
  for (const n of nodes) walk(n, (x) => { if (x.tag) out.add(x.tag); });
  return out;
}

const TWO = [
  "diff --git a/src/a.rs b/src/a.rs",
  "index 1111111..2222222 100644",
  "--- a/src/a.rs",
  "+++ b/src/a.rs",
  "@@ -10,3 +10,4 @@ fn main() {",
  " keep",
  "-old",
  "+new",
  "+more",
  " end",
  "diff --git a/b.txt b/b.txt",
  "new file mode 100644",
  "--- /dev/null",
  "+++ b/b.txt",
  "@@ -0,0 +1 @@",
  "+hello",
  "",
].join("\n");

test("parse counts lines", () => {
  const files = parse(TWO);
  assert.equal(files.length, 2);
  const [a, b] = files;
  assert.equal(a.oldPath, "src/a.rs");
  assert.equal(a.newPath, "src/a.rs");
  assert.equal(a.binary, false);
  assert.equal(b.oldPath, null);
  assert.equal(b.newPath, "b.txt");
  const all = files.flatMap((f) => f.hunks.flatMap((x) => x.lines));
  assert.equal(all.filter((l) => l.kind === "+").length, 3);
  assert.equal(all.filter((l) => l.kind === "-").length, 1);
  assert.equal(a.hunks[0].header, "@@ -10,3 +10,4 @@ fn main() {");
  assert.deepEqual(
    a.hunks[0].lines.map((l) => [l.kind, l.text, l.oldNo, l.newNo]),
    [
      [" ", "keep", 10, 10],
      ["-", "old", 11, null],
      ["+", "new", null, 11],
      ["+", "more", null, 12],
      [" ", "end", 12, 13],
    ],
  );
  assert.deepEqual(b.hunks[0].lines.map((l) => [l.kind, l.text, l.oldNo, l.newNo]), [["+", "hello", null, 1]]);
});

test("parse no newline marker", () => {
  const files = parse("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n\\ No newline at end of file\n");
  assert.equal(files.length, 1);
  assert.deepEqual(
    files[0].hunks[0].lines.map((l) => [l.kind, l.text, l.oldNo, l.newNo]),
    [
      ["-", "a", 1, null],
      ["\\", " No newline at end of file", null, null],
      ["+", "b", null, 1],
      ["\\", " No newline at end of file", null, null],
    ],
  );
});

test("parse rename and binary", () => {
  const files = parse([
    "diff --git a/old name.txt b/new name.txt",
    "similarity index 90%",
    "rename from old name.txt",
    "rename to new name.txt",
    "diff --git a/logo.png b/logo.png",
    "Binary files a/logo.png and b/logo.png differ",
    "",
  ].join("\n"));
  assert.equal(files.length, 2);
  assert.equal(files[0].oldPath, "old name.txt");
  assert.equal(files[0].newPath, "new name.txt");
  assert.equal(files[0].binary, false);
  assert.deepEqual(files[0].hunks, []);
  assert.equal(files[1].oldPath, "logo.png");
  assert.equal(files[1].newPath, "logo.png");
  assert.equal(files[1].binary, true);
  const r = render(files, h, {});
  assert.ok(texts(r.nodes).some((t) => t.includes("binary")), "binary is said");
});

test("parse crlf keeps cr visible", () => {
  const files = parse("--- a/w.txt\r\n+++ b/w.txt\r\n@@ -1 +1 @@\r\n-a\r\n+b\r\n");
  const lines = files[0].hunks[0].lines;
  assert.deepEqual(lines.map((l) => [l.kind, l.text]), [["-", "a\r"], ["+", "b\r"]]);
  const r = render(files, h, {});
  const t = texts(r.nodes);
  assert.ok(t.some((x) => x.includes("b⟨U+000D⟩")), t.join("|"));
  assert.ok(!t.some((x) => x.includes("\r")), "no raw CR reaches the page");
});

// The start of plan 28's demo diff for b-done (crates/wire/src/fake.rs).
const HOSTILE = [
  "diff --git a/../../.ssh/authorized_keys b/../../.ssh/authorized_keys",
  "--- a/../../.ssh/authorized_keys",
  "+++ b/../../.ssh/authorized_keys",
  "@@ -0,0 +1 @@",
  "+ssh-ed25519 AAAA-not-a-real-key attacker",
  "diff --git a/<img src=x onerror=alert(1)>.md b/<img src=x onerror=alert(1)>.md",
  "--- /dev/null",
  "+++ b/<img src=x onerror=alert(1)>.md",
  "@@ -0,0 +1 @@",
  "+\x1b]52;c;ZXZpbA==\x07 a clipboard attempt",
  "diff --git a/logo.png b/logo.png",
  "Binary files a/logo.png and b/logo.png differ",
  "diff --git a/src/big.rs b/src/big.rs",
  "--- a/src/big.rs",
  "+++ b/src/big.rs",
  "+let generated_line_0 = 0; // filler",
  "+let generated_line_1 = 1; // filler",
  "",
].join("\n");

test("diff render keeps hostile text inert", () => {
  const files = parse(HOSTILE);
  assert.deepEqual(files.map((f) => f.newPath), ["../../.ssh/authorized_keys", "<img src=x onerror=alert(1)>.md", "logo.png", "src/big.rs"]);
  const r = render(files, h, {});
  const t = texts(r.nodes);
  // Paths stay literal text, `../` included.
  assert.ok(t.some((x) => x.includes("../../.ssh/authorized_keys")), t.join("|"));
  assert.ok(t.some((x) => x.includes("<img src=x onerror=alert(1)>.md")));
  // The OSC 52 sequence becomes visible escapes.
  assert.ok(t.some((x) => x.includes("⟨ESC⟩]52;c;ZXZpbA==⟨U+0007⟩ a clipboard attempt")), t.join("|"));
  assert.ok(!t.some((x) => /[\x00-\x08\x0b-\x1f\x7f]/.test(x)), "no raw control reaches the page");
  // No element but the renderer's own, no link, no attribute but class.
  for (const tag of tags(r.nodes)) assert.ok(["section", "h3", "div", "pre", "span", "p"].includes(tag), tag);
  for (const n of r.nodes) walk(n, (x) => { if (x.attrs) for (const k of Object.keys(x.attrs)) assert.equal(k, "class"); });
  // The headerless lines of big.rs are still shown.
  assert.ok(t.some((x) => x.includes("generated_line_1")));
  assert.equal(r.shownLines, 4);
  assert.equal(r.hiddenLines, 0);
});

test("diff render caps lines", () => {
  const body = Array.from({ length: 5000 }, (_, i) => `+line ${i}`).join("\n");
  const files = parse(`--- /dev/null\n+++ b/many.txt\n@@ -0,0 +1,5000 @@\n${body}\n`);
  assert.equal(files[0].hunks[0].lines.length, 5000);
  const r = render(files, h, {});
  assert.equal(r.shownLines, 2000);
  assert.equal(r.hiddenLines, 3000);
  const t = texts(r.nodes);
  assert.ok(t.some((x) => x.includes("line 1999")));
  assert.ok(!t.some((x) => x.includes("line 2000")));
  assert.ok(t.some((x) => x.includes("3000 more lines are not shown")), t.slice(-3).join("|"));
  const small = render(files, h, { maxLines: 10 });
  assert.equal(small.shownLines, 10);
  assert.equal(small.hiddenLines, 4990);
});
