#!/usr/bin/env python3
"""Attacker-side IPC client for saiifed's control socket (red-team CI only).

Frame: u32 big-endian length + UTF-8 JSON object, at most 1 MiB.
Runs only in the GitHub locked-linux job; refuses anywhere else.
"""
import json
import os
import socket
import stat
import sys
import threading
import time

MAX_FRAME = 1048576
DEFAULT_SOCKET = "/run/saiife/saiife.sock"


class UsageError(Exception):
    """A caller mistake (bad/missing args): the gate reports it and exits 2."""


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
    """Next frame as decoded JSON, or None on EOF."""
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


def _ans_ok(a):
    return isinstance(a, dict) and a.get("ok") is True


def _ans_busy(a):
    return isinstance(a, dict) and a.get("error") == "busy"


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
        """Send one well-formed frame; the encode path stays strict."""
        self.sock.sendall(encode(obj))

    def send_raw(self, data):
        """Send exactly these bytes, bypassing the length/JSON encoder."""
        self.sock.sendall(data)

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
    now = time.time()
    ms = int(round((now - int(now)) * 1000))
    if ms > 999:
        ms = 999
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % ms
    rec = {
        "v": 2,
        "ts": ts,
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


def raw_send(path, data):
    """Send raw bytes to the daemon, report the one answer or that it closed."""
    c = Conn(path)
    try:
        c.send_raw(data)
        try:
            a = read_frame(c.sock)
        except (OSError, ValueError):
            return {"closed": True}
        if a is None:
            return {"closed": True}
        return {"answer": a}
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
                if _ans_ok(a):
                    ok += 1
                elif _ans_busy(a):
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
        # A short per-connection timeout keeps the worst case bounded even if
        # the daemon accepts but never answers the hello.
        try:
            c = Conn(path, timeout=2.0)
            a = c.hello()
        except (OSError, ValueError):
            refused += 1
            continue
        if a is None:
            refused += 1
            c.close()
            continue
        held.append(c)
        if _ans_busy(a):
            busy += 1
        elif _ans_ok(a):
            ok += 1
        else:
            refused += 1
    time.sleep(1)
    for c in held:
        c.close()
    return {"ok": ok, "busy": busy, "refused": refused}


def _unlink_stale_socket(path):
    """Remove a leftover socket file only if it is a socket we own."""
    try:
        st = os.lstat(path)
    except OSError:
        return
    if stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid():
        try:
            os.unlink(path)
        except OSError:
            pass


def serve_fake(path, count_file, ready=None, stop=None, ready_file=None):
    _unlink_stale_socket(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(64)
    # Open the count file before announcing readiness so an unwritable path is
    # reported here, not as a traceback from an accept loop or handler thread.
    cf = open(count_file, "a")
    try:
        if stop is not None:
            srv.settimeout(0.1)
        if ready_file is not None:
            with open(ready_file, "w") as rf:
                rf.write("ready\n")
        if ready is not None:
            ready.set()

        def handle(c):
            c.settimeout(None)
            try:
                while True:
                    req = read_frame(c)
                    if req is None:
                        break
                    rid = req.get("id") if isinstance(req, dict) else None
                    op = req.get("op") if isinstance(req, dict) else None
                    if op == "hello":
                        a = {"id": rid, "ok": True, "proto": 1,
                             "daemon": "fake", "mode": "locked"}
                    else:
                        a = {"id": rid, "ok": True}
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
            cf.write("conn\n")
            cf.flush()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    finally:
        cf.close()
        srv.close()


def _emit(obj):
    print(json.dumps(obj))


def _take_opt(rest, name):
    """Pull `--name VALUE` out of rest, returning (value_or_None, remaining)."""
    out = []
    val = None
    i = 0
    while i < len(rest):
        if rest[i] == name:
            if i + 1 >= len(rest):
                raise UsageError("%s needs a value" % name)
            val = rest[i + 1]
            i += 2
            continue
        out.append(rest[i])
        i += 1
    return val, out


def _arg(rest, i, what):
    if i >= len(rest):
        raise UsageError("missing argument: %s" % what)
    return rest[i]


def _int_arg(rest, i, what, minimum=None):
    raw = _arg(rest, i, what)
    try:
        v = int(raw)
    except ValueError:
        raise UsageError("%s must be an integer, got %r" % (what, raw))
    if minimum is not None and v < minimum:
        raise UsageError("%s must be >= %d, got %d" % (what, minimum, v))
    return v


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
            raw = _arg(rest, 0, "<json>")
            try:
                rec = json.loads(raw)
            except ValueError as e:
                raise UsageError("append-json needs valid JSON: %s" % e)
            _emit(_hello_append(path, rec))
        elif cmd == "forge-guard":
            rec = guard_record(_arg(rest, 0, "<input>"), uid=0, user="root",
                               mode="developer", seq=1, prev="0" * 64, host="evil",
                               ts="2001-01-01T00:00:00.000Z")
            _emit(_hello_append(path, rec))
        elif cmd == "rotate-key":
            c = Conn(path)
            try:
                c.hello()
                _emit(c.call("audit.rotate_key"))
            finally:
                c.close()
        elif cmd == "raw":
            hexstr, _rest = _take_opt(rest, "--hex")
            if hexstr is None:
                raise UsageError("raw needs --hex <bytes>")
            try:
                data = bytes.fromhex(hexstr)
            except ValueError as e:
                raise UsageError("--hex must be hex digits: %s" % e)
            _emit(raw_send(path, data))
        elif cmd == "raw-frame":
            length, rest = _take_opt(rest, "--length")
            body, rest = _take_opt(rest, "--body")
            if length is None or body is None:
                raise UsageError("raw-frame needs --length N and --body <text>")
            try:
                n = int(length)
            except ValueError:
                raise UsageError("--length must be an integer, got %r" % length)
            if n < 0 or n > 0xFFFFFFFF:
                raise UsageError("--length must fit in u32, got %d" % n)
            data = n.to_bytes(4, "big") + body.encode("utf-8")
            _emit(raw_send(path, data))
        elif cmd == "flood":
            n = _int_arg(rest, 0, "<n>", minimum=0)
            threads = _int_arg(rest, 1, "<threads>", minimum=1)
            _emit(flood(path, n, threads))
        elif cmd == "conns":
            _emit(conns(path, _int_arg(rest, 0, "<n>", minimum=0)))
        elif cmd == "bind":
            target = _arg(rest, 0, "<path>")
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.bind(target)
            except OSError as e:
                _emit({"error": e.strerror})
                print(e.strerror, file=sys.stderr)
                return 1
            finally:
                s.close()
            try:
                os.unlink(target)
            except OSError:
                pass
        elif cmd == "serve-fake":
            ready_file, rest = _take_opt(rest, "--ready-file")
            spath = _arg(rest, 0, "<path>")
            cfile = _arg(rest, 1, "<count-file>")
            serve_fake(spath, cfile, ready_file=ready_file)
        else:
            print("unknown command: %s" % cmd, file=sys.stderr)
            return 2
    except UsageError as e:
        print("usage error: %s" % e, file=sys.stderr)
        return 2
    except (OSError, ValueError, IndexError) as e:
        print("connection failure: %s" % e, file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
