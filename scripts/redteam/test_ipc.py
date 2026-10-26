import contextlib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipc  # noqa: E402

GATE = {"GITHUB_ACTIONS": "true", "SAIIFE_LOCKED_CI": "1"}


class IpcTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def test_encode_round_trip(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        obj = {"id": 1, "op": "hello", "proto": 1}
        data = ipc.encode(obj)
        a.sendall(data)
        self.assertEqual(ipc.read_frame(b), obj)
        self.assertEqual(data[:4], len(data[4:]).to_bytes(4, "big"))
        a.close()
        self.assertIsNone(ipc.read_frame(b))

    def test_encode_rejects_oversize(self):
        with self.assertRaises(ValueError):
            ipc.encode({"a": "x" * ipc.MAX_FRAME})

    def _fake(self):
        path = os.path.join(self.dir, "s.sock")
        count = os.path.join(self.dir, "count")
        ready, stop = threading.Event(), threading.Event()
        t = threading.Thread(target=ipc.serve_fake, args=(path, count, ready, stop))
        t.start()
        self.addCleanup(t.join)
        self.addCleanup(stop.set)
        self.assertTrue(ready.wait(5))
        return path, count

    def test_fake_server_counts_and_answers(self):
        path, count = self._fake()
        c = ipc.Conn(path)
        self.assertEqual(c.hello()["mode"], "locked")
        self.assertIs(c.call("audit.append", rec={})["ok"], True)
        c.close()
        with open(count) as f:
            self.assertEqual(len(f.readlines()), 1)
        c2 = ipc.Conn(path)
        c2.hello()
        c2.close()
        with open(count) as f:
            self.assertEqual(len(f.readlines()), 2)

    def test_guard_record_overrides(self):
        r = ipc.guard_record("x", uid=0)
        self.assertEqual(r["uid"], 0)
        for k in ("v", "ts", "agent", "project", "tool", "input", "decision", "saiife"):
            self.assertIn(k, r)
        self.assertEqual(r["v"], 2)
        self.assertEqual(ipc.guard_record("x", decision="deny")["decision"], "deny")

    def test_main_refuses_without_gate(self):
        env = {k: v for k, v in os.environ.items() if k not in GATE}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(socket, "socket", side_effect=AssertionError("connected")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ipc.main(["hello"]), 2)

    def test_main_against_fake_with_gate(self):
        path, _ = self._fake()
        out = io.StringIO()
        with mock.patch.dict(os.environ, GATE), contextlib.redirect_stdout(out):
            self.assertEqual(ipc.main(["--socket", path, "forge-guard", "x"]), 0)
        self.assertTrue(json.loads(out.getvalue())["ok"])

    def test_raw_oversize_length_header_closes(self):
        path, _ = self._fake()
        # 4-byte header claiming 2 MiB, then a tiny body: the server rejects
        # the length and closes without answering.
        out = self._raw(path, {"--length": str(2 * 1024 * 1024), "--body": "{}"})
        self.assertTrue(out["closed"])

    def test_raw_zero_length_closes(self):
        path, _ = self._fake()
        out = self._raw(path, {"--length": "0", "--body": ""})
        self.assertTrue(out["closed"])

    def test_raw_non_json_body_closes(self):
        path, _ = self._fake()
        out = self._raw(path, {"--length": "5", "--body": "notjs"})
        self.assertTrue(out["closed"])

    def _raw(self, path, opts):
        argv = ["--socket", path, "raw-frame"]
        for k, v in opts.items():
            argv += [k, v]
        out = io.StringIO()
        with mock.patch.dict(os.environ, GATE), contextlib.redirect_stdout(out):
            self.assertEqual(ipc.main(argv), 0)
        return json.loads(out.getvalue())

    def test_serve_fake_ready_file_and_stale_socket(self):
        path = os.path.join(self.dir, "s.sock")
        count = os.path.join(self.dir, "count")
        ready_file = os.path.join(self.dir, "ready")
        # Leave a stale socket of our own at the path; serve_fake must unlink it.
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(path)
        stale.close()
        self.assertTrue(os.path.exists(path))
        stop = threading.Event()
        t = threading.Thread(target=ipc.serve_fake,
                             kwargs={"path": path, "count_file": count,
                                     "stop": stop, "ready_file": ready_file})
        t.start()
        self.addCleanup(t.join)
        self.addCleanup(stop.set)
        for _ in range(50):
            if os.path.exists(ready_file):
                break
            time.sleep(0.05)
        self.assertTrue(os.path.exists(ready_file))
        c = ipc.Conn(path)
        self.assertEqual(c.hello()["mode"], "locked")
        c.close()

    def test_unlink_stale_socket_leaves_plain_file(self):
        plain = os.path.join(self.dir, "plain")
        with open(plain, "w") as f:
            f.write("not a socket")
        ipc._unlink_stale_socket(plain)
        self.assertTrue(os.path.exists(plain))

    def test_usage_errors_exit_2(self):
        with mock.patch.dict(os.environ, GATE), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ipc.main(["append-json", "{not json"]), 2)
            self.assertEqual(ipc.main(["flood", "100", "0"]), 2)
            self.assertEqual(ipc.main(["append-json"]), 2)
            self.assertEqual(ipc.main(["conns"]), 2)

    def test_guard_record_ts_has_millis(self):
        ts = ipc.guard_record("x")["ts"]
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_non_dict_answer_handled(self):
        # A server that answers with a bare JSON number must not crash conns().
        path = os.path.join(self.dir, "weird.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(8)
        self.addCleanup(srv.close)

        def serve():
            try:
                while True:
                    conn, _ = srv.accept()
                    ipc.read_frame(conn)
                    conn.sendall(ipc.encode(42))
                    conn.close()
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        res = ipc.conns(path, 1)
        self.assertEqual(res["refused"], 1)

    def test_bind_reports_permission_error(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores directory modes")
        ro = os.path.join(self.dir, "ro")
        os.mkdir(ro, 0o500)
        out = io.StringIO()
        with mock.patch.dict(os.environ, GATE), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = ipc.main(["bind", os.path.join(ro, "x.sock")])
        self.assertEqual(rc, 1)
        self.assertIn("Permission denied", json.loads(out.getvalue())["error"])


if __name__ == "__main__":
    unittest.main()
