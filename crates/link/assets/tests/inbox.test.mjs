import test from "node:test";
import assert from "node:assert/strict";
import { className, timeLeft, taskCounter, checkRepo, checkTask, needsTouchBadge, spawnArgs, templateLabel, credentialLabel, noticeText, MAX_TASK_BYTES } from "../js/inboxlogic.js";

test("class names as words", () => {
  assert.equal(className("land"), "Land into repo");
  assert.equal(className("push_protected"), "Push to protected branch");
  assert.equal(className("deploy"), "Deploy");
  assert.equal(className("secret:sensitive"), "Use a sensitive secret");
  assert.equal(className("egress:external"), "Reach the outside network");
  assert.equal(className("x<b>"), "x<b>");
});

test("time left", () => {
  assert.deepEqual(timeLeft(1300, 1000), { expired: false, text: "5 min left" });
  assert.deepEqual(timeLeft(1030, 1000), { expired: false, text: "30 s left" });
  assert.deepEqual(timeLeft(1000, 1000), { expired: true, text: "expired" });
  assert.deepEqual(timeLeft(900, 1000), { expired: true, text: "expired" });
  assert.equal(timeLeft("nope", 1000).expired, true);
});

test("task counter counts bytes", () => {
  assert.deepEqual(taskCounter("é"), { text: `2 / ${MAX_TASK_BYTES} bytes`, over: false });
  assert.equal(taskCounter("a".repeat(8192)).over, false);
  assert.equal(taskCounter("a".repeat(8193)).over, true);
});

test("repo and task validation", () => {
  assert.equal(checkRepo(""), "Enter a repo name.");
  assert.equal(checkRepo("r".repeat(201)), "The repo name is at most 200 characters.");
  assert.equal(checkRepo("r"), null);
  assert.equal(checkRepo("r".repeat(200)), null);
  assert.equal(checkTask(""), "Describe the task.");
  assert.equal(checkTask("a".repeat(8193)), "The task is at most 8192 bytes.");
  assert.equal(checkTask("do it"), null);
});

test("needs-a-touch badge", () => {
  assert.equal(needsTouchBadge({ has_secrets: true, has_egress: false }), true);
  assert.equal(needsTouchBadge({ has_secrets: false, has_egress: true }), true);
  assert.equal(needsTouchBadge({ has_secrets: false, has_egress: false }), false);
});

test("spawn args", () => {
  assert.deepEqual(spawnArgs("claude", "r", "t", true), { template: "claude", repo: "r", task: "t", start: "now" });
  assert.deepEqual(spawnArgs("claude", "r", "t", false).start, "queue");
});

import { promptAction } from "../js/inboxlogic.js";
test("prompt action", () => {
  assert.equal(promptAction("land"), "box.land");
  assert.equal(promptAction("push_protected"), "class:push_protected");
});

test("steer class has words (TouchClass::Steer)", () => {
  assert.equal(className("steer"), "Steer a box");
});

test("templateLabel marks beta", () => {
  assert.equal(templateLabel({ name: "codex", beta: true }), "codex (beta)");
  assert.equal(templateLabel({ name: "claude-code" }), "claude-code");
  assert.equal(templateLabel({ name: "x", beta: "yes" }), "x");
});

test("credentialLabel follows the credential mode", () => {
  assert.equal(credentialLabel({ credential: "gateway" }), "key stays on this computer");
  assert.equal(credentialLabel({}), "key stays on this computer");
  assert.equal(credentialLabel({ credential: "in_box" }), "credential inside box (weaker)");
});

test("templateLabel and credentialLabel take untrusted names through visible()", () => {
  const s = templateLabel({ name: "a‮b", beta: true });
  assert.ok(!s.includes("‮"), s);
  assert.ok(s.includes("U+202E"), s);
  assert.equal(credentialLabel({ credential: "a‮b" }), "key stays on this computer");
});

test("noticeText shows the notice through visible()", () => {
  assert.equal(noticeText({}), "");
  assert.equal(noticeText({ notice: "use a key" }), "use a key");
  assert.ok(!noticeText({ notice: "a‮b" }).includes("‮"));
});
