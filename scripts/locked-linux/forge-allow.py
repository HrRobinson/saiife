"""Forge a hook's allow over the control socket (plan 21, Linux and macOS).

CI ONLY: scripts/locked-linux/lib.sh and scripts/locked-macos/lib.sh
`phase_forge` run it as the agent user, on a throwaway runner, with
`python3 -I -` and this file on stdin (the agent user may not be able to
read the checkout):

    python3 -I - forge <control socket> <payload JSON text> [hold seconds]

It does what any process of the agent's user can do with no code injection
(spec §9.2 A25): it connects to the daemon's control socket, checks nothing
(an attacker would not), and sends the §8.7 frames the managed hook sends:

  1. `hello`;
  2. `hook.begin {agent: "claude", event: "PreToolUse"}`;
  3. `hook.bind` with the payload's key (`saiife_ipc::hookkey`: the agent,
     the session, the tool call id and the SHA-256 of the canonical JSON of
     `tool_input`);
  4. `audit.append` of a guard record with `decision: "allow"`, the key's
     `tool_use_id` and `input_sha256` beside it, as the hook sends them.

The daemon then holds the forger's allow for the key. The co-signer must
still deny a call the policy denies: its own judgment of the body Claude
Code sent disagrees (plan 21). The connection is held open for `hold`
seconds (default 0) after the append, then closed.

    python3 -I - key <payload file>

prints only the payload's `input_sha256`, for the CI check against the
hook's own hash (crates/ipc/src/hookkey.rs `key_of_the_claude_fixture`).
It reads a file and connects to nothing.

Output: key=value lines. Exit 0 when every step was answered `ok`, 1 when
the daemon refused one (the refusal is printed), 2 on bad arguments, 3 when
the forger could not run (no socket, a broken frame). Standard library only.
"""

import hashlib
import json
import os
import socket
import struct
import sys
import time

PROTO = 1
# The daemon's request cap (crates/ipc/src/frame.rs MAX_FRAME) and its
# answer cap (MAX_ANSWER_FRAME).
MAX_FRAME = 1_048_576
MAX_ANSWER = 16 * 1_048_576
DEADLINE_S = 10.0


class Refused(Exception):
    pass


class Broken(Exception):
    pass


def canonical(v):
    """`hookkey::canonical_sha256`'s text: compact, every object's keys sorted
    by byte order (code point order is the same for UTF-8), serde_json's
    string escapes (only `"`, `\\` and control characters; UTF-8 kept).
    Floats are refused: serde_json prints them with ryu, Python with repr,
    and the two differ (1e16). No CI payload has one."""
    if isinstance(v, bool) or v is None or isinstance(v, int):
        return json.dumps(v)
    if isinstance(v, float):
        raise ValueError("a float in tool_input: this forger hashes integers only")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-8"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(x) for k, x in items) + "}"
    raise ValueError(f"not JSON: {type(v).__name__}")


def first(m, *names, want=None):
    """The first of `names` in `m` that is present: for strings, a non-empty
    string (else absent); for the input, a non-null value."""
    for n in names:
        x = m.get(n)
        if want is str:
            if isinstance(x, str) and x:
                return x
        elif x is not None:
            return x
    return None


def key_of(payload):
    """`hookkey::hook_key_value("claude", payload)`."""
    if not isinstance(payload, dict):
        raise ValueError("the payload is not a JSON object")
    tool_input = first(payload, "tool_input", "toolInput")
    return {
        "agent": "claude",
        "session": first(payload, "session_id", "sessionId", want=str),
        "tool_use_id": first(payload, "tool_use_id", "toolUseId", want=str),
        "input_sha256": hashlib.sha256(canonical(tool_input).encode("utf-8")).hexdigest(),
    }


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        part = s.recv(n - len(buf))
        if not part:
            raise Broken("the daemon closed the connection")
        buf += part
    return buf


class Conn:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(DEADLINE_S)
        self.s.connect(path)
        self.next_id = 1

    def call(self, op, args):
        rid = self.next_id
        self.next_id += 1
        req = {"id": rid, "op": op}
        req.update(args)
        body = json.dumps(req, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if not body or len(body) > MAX_FRAME:
            raise Broken(f"{op}: a frame of {len(body)} bytes")
        self.s.sendall(struct.pack(">I", len(body)) + body)
        (n,) = struct.unpack(">I", recv_exact(self.s, 4))
        if n == 0 or n > MAX_ANSWER:
            raise Broken(f"{op}: an answer frame of {n} bytes")
        ans = json.loads(recv_exact(self.s, n).decode("utf-8"))
        if not isinstance(ans, dict) or ans.get("id") != rid:
            raise Broken(f"{op}: the answer is not for request {rid}: {ans}")
        if ans.get("ok") is not True:
            raise Refused(f"{op}: {ans.get('error')}: {ans.get('message')}")
        return ans

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def say(k, v):
    print(f"{k}={v}", flush=True)


def forge(path, payload_text, hold):
    payload = json.loads(payload_text)
    key = key_of(payload)
    ti = payload.get("tool_input")
    command = ti.get("command") if isinstance(ti, dict) else None
    say("forger_pid", os.getpid())
    say("input_sha256", key["input_sha256"])
    say("tool_use_id", key["tool_use_id"])
    c = Conn(path)
    try:
        ans = c.call("hello", {"proto": PROTO, "client": "forge-allow"})
        say("hello", f"ok mode={ans.get('mode')}")
        c.call("hook.begin", {"agent": "claude", "event": payload.get("hook_event_name") or "PreToolUse"})
        say("begin", "ok")
        bind = dict(key)
        if isinstance(payload.get("tool_name"), str):
            bind["tool"] = payload["tool_name"]
        c.call("hook.bind", bind)
        say("bind", "ok")
        rec = {
            "v": 1,
            "agent": "claude",
            "project": payload.get("cwd") or "",
            "session": key["session"],
            "tool": payload.get("tool_name") or "unknown",
            "input": command if isinstance(command, str) else "",
            "decision": "allow",
            "saiife": "forge-allow",
        }
        args = {"rec": rec, "input_sha256": key["input_sha256"]}
        if key["tool_use_id"]:
            args["tool_use_id"] = key["tool_use_id"]
        ans = c.call("audit.append", args)
        say("append", f"ok seq={ans.get('seq')}")
        if hold > 0:
            time.sleep(hold)
            say("held_s", hold)
    finally:
        c.close()


def main(argv):
    if len(argv) == 3 and argv[1] == "key":
        with open(argv[2], encoding="utf-8") as f:
            print(key_of(json.load(f))["input_sha256"])
        return 0
    if len(argv) in (4, 5) and argv[1] == "forge":
        hold = float(argv[4]) if len(argv) == 5 else 0.0
        try:
            forge(argv[2], argv[3], hold)
        except Refused as e:
            say("refused", e)
            return 1
        except (OSError, Broken, ValueError) as e:
            say("error", f"{type(e).__name__}: {e}")
            return 3
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
