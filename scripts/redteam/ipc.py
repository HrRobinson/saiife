#!/usr/bin/env python3
"""Attacker-side IPC client for saiifed's control socket (red-team CI only).

Frame: u32 big-endian length + UTF-8 JSON object, at most 1 MiB.
Runs only in the GitHub locked-linux job; refuses anywhere else.
"""
import json
import os
import socket
import sys
import threading
import time

MAX_FRAME = 1048576
DEFAULT_SOCKET = "/run/saiife/saiife.sock"


def encode(obj):
    body = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise ValueError("frame of %d bytes exceeds the 1 MiB limit" % len(body))
    return len(body).to_bytes(4, "big") + body


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_frame(sock):
    """Next frame as a dict, or None on EOF."""
    h = _recv_exact(sock, 4)
    if h is None:
        return None
    n = int.from_bytes(h, "big")
    if n == 0 or n > MAX_FRAME:
        raise ValueError("bad frame length %d" % n)
    body = _recv_exact(sock, n)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


class Conn:
    def __init__(self, path, timeout=5.0):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect(path)
        except OSError:
            self.sock.close()
            raise
        self._next = 2

    def send(self, obj):
        self.sock.sendall(encode(obj))

    def hello(self):
        self.send({"id": 1, "op": "hello", "proto": 1, "client": "redteam"})
        return read_frame(self.sock)

    def call(self, op, **args):
        i = self._next
        self._next += 1
        req = {"id": i, "op": op}
        req.update(args)
        self.send(req)
        return read_frame(self.sock)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def guard_record(input, **override):
    rec = {
        "v": 2,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z",
        "agent": "claude",
        "project": "/tmp",
        "tool": "Bash",
        "input": input,
        "decision": "allow",
        "saiife": "redteam",
    }
    rec.update(override)
    return rec


def _hello_append(path, rec):
    c = Conn(path)
    try:
        c.hello()
        return c.call("audit.append", rec=rec)
    finally:
        c.close()


def _flood_worker(path, count, stats, lock):
    ok = busy = other = 0
    try:
        c = Conn(path, timeout=30.0)
    except OSError:
        with lock:
            stats["other"] += count
        return
    try:
        c.hello()
        rec = guard_record("rt-a09-flood")

        def writer():
            try:
                for i in range(count):
                    c.send({"id": i + 2, "op": "audit.append", "rec": rec})
            except OSError:
                pass

        t = threading.Thread(target=writer)
        t.start()
        got = 0
        try:
            while got < count:
                a = read_frame(c.sock)
                if a is None:
                    break
                got += 1
                if a.get("ok"):
                    ok += 1
                elif a.get("error") == "busy":
                    busy += 1
                else:
                    other += 1
        except (OSError, ValueError):
            pass
        t.join()
        other += count - got
    finally:
        c.close()
    with lock:
        stats["ok"] += ok
        stats["busy"] += busy
        stats["other"] += other


def flood(path, n, threads):
    stats = {"ok": 0, "busy": 0, "other": 0}
    lock = threading.Lock()
    per = n // threads
    t0 = time.time()
    ts = [threading.Thread(target=_flood_worker, args=(path, per, stats, lock))
          for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    out = {"sent": per * threads}
    out.update(stats)
    out["elapsed_s"] = round(time.time() - t0, 3)
    return out


def conns(path, n):
    held = []
    ok = busy = refused = 0
    for _ in range(n):
        try:
            c = Conn(path)
            a = c.hello()
        except OSError:
            refused += 1
            continue
        if a is None:
            refused += 1
            c.close()
            continue
        held.append(c)
        if a.get("error") == "busy":
            busy += 1
        elif a.get("ok"):
            ok += 1
        else:
            refused += 1
    time.sleep(1)
    for c in held:
        c.close()
    return {"ok": ok, "busy": busy, "refused": refused}


def serve_fake(path, count_file, ready=None, stop=None):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(64)
    if stop is not None:
        srv.settimeout(0.1)
    if ready is not None:
        ready.set()

    def handle(c):
        c.settimeout(None)
        try:
            while True:
                req = read_frame(c)
                if req is None:
                    break
                if req.get("op") == "hello":
                    a = {"id": req.get("id"), "ok": True, "proto": 1,
                         "daemon": "fake", "mode": "locked"}
                else:
                    a = {"id": req.get("id"), "ok": True}
                c.sendall(encode(a))
        except (OSError, ValueError):
            pass
        finally:
            c.close()

    while stop is None or not stop.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        with open(count_file, "a") as f:
            f.write("conn\n")
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    srv.close()


def _emit(obj):
    print(json.dumps(obj))


def main(argv):
    if not (os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("SAIIFE_LOCKED_CI") == "1"):
        print("refusing: red-team scripts run only in the GitHub locked-linux job",
              file=sys.stderr)
        return 2
    argv = list(argv)
    path = DEFAULT_SOCKET
    if len(argv) >= 2 and argv[0] == "--socket":
        path = argv[1]
        argv = argv[2:]
    if not argv:
        print("usage: ipc.py [--socket PATH] <cmd> ...", file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "hello":
            c = Conn(path)
            try:
                _emit(c.hello())
            finally:
                c.close()
        elif cmd == "append-json":
            _emit(_hello_append(path, json.loads(rest[0])))
        elif cmd == "forge-guard":
            rec = guard_record(rest[0], uid=0, user="root", mode="developer", seq=1,
                               prev="0" * 64, host="evil", ts="2001-01-01T00:00:00.000Z")
            _emit(_hello_append(path, rec))
        elif cmd == "rotate-key":
            c = Conn(path)
            try:
                c.hello()
                _emit(c.call("audit.rotate_key"))
            finally:
                c.close()
        elif cmd == "flood":
            _emit(flood(path, int(rest[0]), int(rest[1])))
        elif cmd == "conns":
            _emit(conns(path, int(rest[0])))
        elif cmd == "bind":
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.bind(rest[0])
            except OSError as e:
                _emit({"error": e.strerror})
                print(e.strerror, file=sys.stderr)
                return 1
            finally:
                s.close()
            try:
                os.unlink(rest[0])
            except OSError:
                pass
        elif cmd == "serve-fake":
            serve_fake(rest[0], rest[1])
        else:
            print("unknown command: %s" % cmd, file=sys.stderr)
            return 2
    except (OSError, ValueError, IndexError) as e:
        print("connection failure: %s" % e, file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
