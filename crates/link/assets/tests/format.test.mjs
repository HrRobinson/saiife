import test from "node:test";
import assert from "node:assert/strict";
import { visible, ago, runtime, short, bytes } from "../js/format.js";

test("visible escapes bidi and controls", () => {
  assert.equal(visible("a‮b"), "a⟨U+202E⟩b");
  assert.equal(visible("\u001b]52;c;x\u0007"), "⟨ESC⟩]52;c;x⟨U+0007⟩");
  assert.equal(visible("x\u007f"), "x⟨U+007F⟩");
  assert.equal(visible("⁦⁩‎‏"), "⟨U+2066⟩⟨U+2069⟩⟨U+200E⟩⟨U+200F⟩");
  assert.equal(visible("plain\ttext\n"), "plain\ttext\n");
  assert.equal(visible(null), "");
});

test("ago and runtime", () => {
  assert.equal(ago(5), "5 s");
  assert.equal(ago(180), "3 min");
  assert.equal(ago(7200), "2 h");
  assert.equal(ago(3 * 86400), "3 d");
  assert.equal(runtime(1000, 1000 + 90), "1 min");
  assert.equal(runtime(1000, 1000 + 3600 * 5), "5 h");
  assert.equal(runtime(1000, 900), "0 s");
  assert.equal(short("0123456789abcdef"), "01234567");
  assert.equal(short("0123456789abcdef", 4), "0123");
  assert.equal(bytes(512), "512 B");
  assert.equal(bytes(2048), "2.0 KiB");
  assert.equal(bytes(3 * 1024 * 1024), "3.0 MiB");
});
