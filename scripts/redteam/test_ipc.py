import contextlib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
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
