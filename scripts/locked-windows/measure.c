/*
 * The measurements of scripts/locked-windows (phase_measurements). CI only. Native, so
 * that a remapped C: cannot break the prober's own lazy loading, as it would in pwsh.
 *
 * These are not tests of a promise. lib.ps1 records what happens and asserts nothing
 * about the result; the owner reads them to decide how Windows locked mode is described.
 * Each runs as the non-admin account `agent` on the throwaway runner, and touches only
 * the session of that account and files on the runner. Global\ device names are not tried.
 *
 *   measure dosdevice <fake root, volume-relative> <ready file> <hook path> <hold seconds>
 *       DefineDosDevice maps C: for this logon session to a dir the agent owns; a child
 *       is then started by the hook's normal path. Removed at the end.
 *   measure hold <path> <ready file> <stop file> <max seconds>
 *       Opens <path> for reading with share mode 0, until <stop file> exists.
 *   measure spawn-hold <hook> <agent> <pid file> <wait seconds>
 *       Starts the hook with a stdin that stays open; prints how it ended. Another
 *       process does the killing.
 *   measure spawn-kill <hook> <agent> <exit code>
 *       The same, and ends the hook itself with TerminateProcess(hook, <exit code>).
 *   measure terminate <pid> <exit code>
 *       OpenProcess(PROCESS_TERMINATE) and TerminateProcess on someone else's pid.
 *
 * Output: key=value lines.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static void say_err(const char *key) {
    printf("%s_error=%lu\n", key, GetLastError());
    fflush(stdout);
}

static void say_w(const char *key, const wchar_t *value) {
    printf("%s=%ls\n", key, value);
    fflush(stdout);
}

static void touch(const wchar_t *path) {
    HANDLE f = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        CloseHandle(f);
    }
}

static int dosdevice(const wchar_t *fake, const wchar_t *ready_path, const wchar_t *hook, int hold) {
    wchar_t device[1024], target[2048], now[1024], final_path[1024];
    wchar_t cmd[2048];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = 0, wrote = 0;
    HANDLE h;
    /* Opened now: after the remap C: no longer reaches this path. */
    HANDLE ready = CreateFileW(ready_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

    if (ready == INVALID_HANDLE_VALUE) {
        say_err("ready_file");
        return 3;
    }
    if (!QueryDosDeviceW(L"C:", device, 1024)) {
        say_err("query_before");
        return 3;
    }
    say_w("c_before", device);
    swprintf(target, 2048, L"%ls%ls", device, fake);
    if (!DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM, L"C:", target)) {
        say_err("define");
        WriteFile(ready, "refused", 7, &wrote, NULL);
        CloseHandle(ready);
        return 0;
    }
    printf("define=succeeded\n");
    if (QueryDosDeviceW(L"C:", now, 1024)) {
        say_w("c_after", now);
    }
    h = CreateFileW(hook, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        say_err("hook_path_open");
    } else {
        if (GetFinalPathNameByHandleW(h, final_path, 1024, VOLUME_NAME_NT)) {
            say_w("hook_path_is", final_path);
        }
        CloseHandle(h);
    }
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    swprintf(cmd, 2048, L"\"%ls\" check --managed --hook-exit --agent claude", hook);
    if (CreateProcessW(hook, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        GetExitCodeProcess(pi.hProcess, &code);
        printf("child_exit=%lu\n", code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        say_err("child_create");
    }
    fflush(stdout);
    WriteFile(ready, "mapped", 6, &wrote, NULL);
    CloseHandle(ready);
    Sleep((DWORD)hold * 1000);
    if (!DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE |
                              DDD_NO_BROADCAST_SYSTEM,
                          L"C:", target)) {
        say_err("remove");
    }
    return 0;
}

static int hold(const wchar_t *path, const wchar_t *ready, const wchar_t *stop, int max_seconds) {
    HANDLE f = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    int i;
    if (f == INVALID_HANDLE_VALUE) {
        say_err("open");
        touch(ready);
        return 0;
    }
    printf("open=succeeded\n");
    fflush(stdout);
    touch(ready);
    for (i = 0; i < max_seconds * 4; i++) {
        if (GetFileAttributesW(stop) != INVALID_FILE_ATTRIBUTES) {
            break;
        }
        Sleep(250);
    }
    CloseHandle(f);
    return 0;
}

/* Starts the hook with a stdin nobody writes to. *pi is the caller's to close. */
static int spawn_hook(const wchar_t *hook, const wchar_t *agent, PROCESS_INFORMATION *pi) {
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE in_read, in_write;
    STARTUPINFOW si;
    wchar_t cmd[2048];

    if (!CreatePipe(&in_read, &in_write, &sa, 0)) {
        say_err("pipe");
        return 0;
    }
    SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_read;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    swprintf(cmd, 2048, L"\"%ls\" check --managed --hook-exit --agent %ls", hook, agent);
    if (!CreateProcessW(hook, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, pi)) {
        say_err("hook_create");
        return 0;
    }
    /* in_write stays open on purpose: the hook waits on stdin, until its own watchdog. */
    CloseHandle(in_read);
    return 1;
}

static int spawn_hold(const wchar_t *hook, const wchar_t *agent, const wchar_t *pid_file, int wait) {
    PROCESS_INFORMATION pi;
    DWORD code = 0, wrote = 0;
    char text[32];
    HANDLE f;
    int n;

    if (!spawn_hook(hook, agent, &pi)) {
        return 3;
    }
    f = CreateFileW(pid_file, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        say_err("pid_file");
        return 3;
    }
    n = sprintf(text, "%lu", pi.dwProcessId);
    WriteFile(f, text, (DWORD)n, &wrote, NULL);
    CloseHandle(f);
    WaitForSingleObject(pi.hProcess, (DWORD)wait * 1000);
    GetExitCodeProcess(pi.hProcess, &code);
    printf("child_exit=%lu\n", code);
    fflush(stdout);
    return 0;
}

static int spawn_kill(const wchar_t *hook, const wchar_t *agent, UINT exit_code) {
    PROCESS_INFORMATION pi;
    DWORD code = 0;

    if (!spawn_hook(hook, agent, &pi)) {
        return 3;
    }
    Sleep(300);
    if (TerminateProcess(pi.hProcess, exit_code)) {
        printf("terminate=succeeded\n");
    } else {
        say_err("terminate");
    }
    WaitForSingleObject(pi.hProcess, 10000);
    GetExitCodeProcess(pi.hProcess, &code);
    printf("child_exit=%lu\n", code);
    fflush(stdout);
    return 0;
}

static int terminate(DWORD pid, UINT exit_code) {
    HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (p == NULL) {
        say_err("open_process");
        return 0;
    }
    if (TerminateProcess(p, exit_code)) {
        printf("terminate=succeeded\n");
    } else {
        say_err("terminate");
    }
    fflush(stdout);
    CloseHandle(p);
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 6 && wcscmp(argv[1], L"dosdevice") == 0) {
        return dosdevice(argv[2], argv[3], argv[4], _wtoi(argv[5]));
    }
    if (argc == 6 && wcscmp(argv[1], L"hold") == 0) {
        return hold(argv[2], argv[3], argv[4], _wtoi(argv[5]));
    }
    if (argc == 6 && wcscmp(argv[1], L"spawn-hold") == 0) {
        return spawn_hold(argv[2], argv[3], argv[4], _wtoi(argv[5]));
    }
    if (argc == 5 && wcscmp(argv[1], L"spawn-kill") == 0) {
        return spawn_kill(argv[2], argv[3], (UINT)_wtoi(argv[4]));
    }
    if (argc == 4 && wcscmp(argv[1], L"terminate") == 0) {
        return terminate((DWORD)_wtoi(argv[2]), (UINT)_wtoi(argv[3]));
    }
    fprintf(stderr, "usage: see measure.c\n");
    return 2;
}
