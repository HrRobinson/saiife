"""Can a process of the hook's own user trace the managed hook? (plan 20, Linux)

CI ONLY: scripts/locked-linux/lib.sh `phase_ptrace` runs it as the agent user,
on a throwaway runner, with `python3 -I -` and this file on stdin:

    python3 -I - <protected binary> <control binary>

For each binary it starts `<binary> check --managed --hook-exit --agent
claude` as its own child, with stdin held open, so the hook waits for its
payload and the probe is its parent (Yama's ptrace_scope=1 allows a parent).
It then tries what the agent's user could do to a hook it did not start:

  * PTRACE_ATTACH;
  * open /proc/<pid>/mem for reading;
  * read the Uid line of /proc/<pid>/status, which shows that the hook runs
    as this same user (so a refusal is not a uid mismatch).

Expected: the protected binary (/opt/saiife/bin/saiife, root:root 0711) is
not dumpable, so the attach fails with EPERM and the open with EACCES or
EPERM. The control (a 0755 copy owned by the agent user, the same bytes)
attaches and opens: it shows that the probe and the runner can trace at all.
Each child is then let go: detached if attached, its stdin closed, and
waited for. A child that does not end in 15 s is killed; it is this probe's
own child.

Exit 0 when both results are as expected, 1 when one is not, 3 when the
probe could not run (a child ended before the probe, no ctypes, ...).
Standard library only.
"""

import ctypes
import errno
import os
import subprocess
import sys
import time

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
WALL = 0x40000000  # __WALL


def comm_of(pid):
    with open(f"/proc/{pid}/comm", encoding="utf-8") as f:
        return f.read().strip()


def uid_of(pid):
    with open(f"/proc/{pid}/status", encoding="utf-8") as f:
        for line in f:
            if line.startswith("Uid:"):
                return int(line.split()[1])
    raise RuntimeError(f"no Uid line in /proc/{pid}/status")


def start(binary):
    """The hook as our child, after its exec (its comm is the binary's name)."""
    child = subprocess.Popen(
        [binary, "check", "--managed", "--hook-exit", "--agent", "claude"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    want = os.path.basename(binary)[:15]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError(f"{binary} exited ({child.returncode}) before the probe")
        try:
            if comm_of(child.pid) == want:
                # Past the exec; give it a moment to reach its stdin read.
                time.sleep(0.3)
                return child
        except OSError:
            pass
        time.sleep(0.02)
    stop(child)
    raise RuntimeError(f"{binary}: no exec seen in 5 s")


def stop(child):
    try:
        child.stdin.close()
    except OSError:
        pass
    try:
        child.wait(timeout=15)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def probe(libc, binary):
    """(attach errno or 0, open errno or 0, the hook's uid)"""
    child = start(binary)
    try:
        pid = child.pid
        uid = uid_of(pid)
        ctypes.set_errno(0)
        rc = libc.ptrace(PTRACE_ATTACH, pid, None, None)
        attach = 0 if rc == 0 else ctypes.get_errno()
        if rc == 0:
            # Stopped by the attach: wait for the stop, then let it go.
            os.waitpid(pid, WALL)
            libc.ptrace(PTRACE_DETACH, pid, None, None)
        try:
            fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
            os.close(fd)
            opened = 0
        except OSError as e:
            opened = e.errno
        if child.poll() is not None:
            raise RuntimeError(f"{binary} exited ({child.returncode}) during the probe")
        return attach, opened, uid
    finally:
        stop(child)


def name(e):
    return "ok" if e == 0 else errno.errorcode.get(e, str(e))


def main():
    if len(sys.argv) != 3:
        print("usage: python3 -I - <protected binary> <control binary>", file=sys.stderr)
        return 3
    protected, control = sys.argv[1], sys.argv[2]
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
        me = os.getuid()
        p_attach, p_open, p_uid = probe(libc, protected)
        c_attach, c_open, c_uid = probe(libc, control)
    except Exception as e:  # noqa: BLE001 - any failure here means "could not probe"
        print(f"FAIL: the probe could not run: {e}")
        return 3

    print(f"protected {protected}: uid {p_uid} (probe uid {me}), "
          f"PTRACE_ATTACH {name(p_attach)}, open /proc/<pid>/mem {name(p_open)}")
    print(f"control {control}: uid {c_uid}, "
          f"PTRACE_ATTACH {name(c_attach)}, open /proc/<pid>/mem {name(c_open)}")
    bad = []
    if p_uid != me or c_uid != me:
        bad.append(f"a hook does not run as the probe's uid {me}")
    if p_attach != errno.EPERM:
        bad.append(f"PTRACE_ATTACH on the protected hook: {name(p_attach)}, want EPERM")
    if p_open not in (errno.EACCES, errno.EPERM):
        bad.append(f"open /proc/<pid>/mem of the protected hook: {name(p_open)}, want EACCES or EPERM")
    if c_attach != 0:
        bad.append(f"the control could not be attached ({name(c_attach)}): the probe proves nothing")
    if c_open != 0:
        bad.append(f"the control's /proc/<pid>/mem could not be opened ({name(c_open)})")
    for b in bad:
        print(f"FAIL: {b}")
    if not bad:
        print("ok: the 0711 hook refuses its own user's ptrace and /proc/<pid>/mem; the 0755 control does not")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
