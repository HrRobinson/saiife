// Pure helpers for the Approve inbox and Spawn screens. No DOM.
import { ago } from "./format.js";

export const MAX_TASK_BYTES = 8192;
export const MAX_REPO_CHARS = 200;

const CLASSES = {
  land: "Land into repo",
  push_protected: "Push to protected branch",
  deploy: "Deploy",
  "secret:sensitive": "Use a sensitive secret",
  "egress:external": "Reach the outside network",
  touch_enrol: "Add a passkey",
  touch_remove: "Remove a passkey",
  touch_test: "Test a passkey",
};

// A touch class as words; an unknown class is shown as it came (the view escapes it).
export function className(c) {
  return typeof c === "string" && Object.hasOwn(CLASSES, c) ? CLASSES[c] : String(c);
}

// Time left until expires_at (unix seconds) at `now`.
export function timeLeft(expiresAt, now) {
  const left = Number(expiresAt) - now;
  if (!Number.isFinite(left) || left <= 0) return { expired: true, text: "expired" };
  return { expired: false, text: `${ago(left)} left` };
}

export function byteLength(s) {
  return new TextEncoder().encode(String(s)).length;
}

export function taskCounter(s) {
  const n = byteLength(s);
  return { text: `${n} / ${MAX_TASK_BYTES} bytes`, over: n > MAX_TASK_BYTES };
}

// -> a message, or null when fine.
export function checkRepo(s) {
  const n = Array.from(String(s)).length;
  if (n === 0) return "Enter a repo name.";
  if (n > MAX_REPO_CHARS) return `The repo name is at most ${MAX_REPO_CHARS} characters.`;
  return null;
}

export function checkTask(s) {
  if (String(s) === "") return "Describe the task.";
  if (byteLength(s) > MAX_TASK_BYTES) return `The task is at most ${MAX_TASK_BYTES} bytes.`;
  return null;
}

export function needsTouchBadge(t) {
  return Boolean(t && (t.has_secrets || t.has_egress));
}

// The args of box.spawn; the daemon's names and values.
export function spawnArgs(template, repo, task, now) {
  return { template, repo, task, start: now ? "now" : "queue" };
}
