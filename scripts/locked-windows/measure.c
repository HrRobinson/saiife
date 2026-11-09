/*
 * The measurements of scripts/locked-windows (phase_measurements). CI only. Native, so
 * that a remapped C: cannot break the prober's own lazy loading, as it would in pwsh.
 *
 * These are not tests of a promise, apart from the two co-signer modes at the end.
 * lib.ps1 records what happens and asserts nothing about the result; the owner reads
 * them to decide how Windows locked mode is described.
 * Each runs as the non-admin account `agent` on the throwaway runner, and touches only
 * the session of that account and files on the runner. Global\ device names are not tried.
 *
 *   measure dosdevice <fake root, volume-relative> <ready file> <hook path> <hold seconds>
 *       DefineDosDevice maps C: for this logon session to a dir the agent owns; a child
 *       is then started by the hook's normal path. Removed at the end.
 *   measure hold <path> <ready file> <stop file> <max seconds>
 *       Opens <path> for reading with share mode 0, until <stop file> exists.
 *   measure spawn-hold <hook> <agent> <pid file> <wait seconds>
 *       Starts the hook with a stdin that stays open; prints the hook's token (user,
 *       groups, the logon SID marked) and its process descriptor as SDDL, then how it
 *       ended. Another process does the killing.
 *   measure spawn-kill <hook> <agent> <exit code>
 *       The same, and ends the hook itself with TerminateProcess(hook, <exit code>).
 *   measure terminate <pid> <exit code>
 *       Prints its own token (the killer's user and groups, the logon SID marked) and
 *       the target's descriptor as far as it may read it, then OpenProcess(
 *       PROCESS_TERMINATE) and TerminateProcess on someone else's pid. A logon SID the
 *       killer shares with the hook would explain a cross-user kill.
 *
 * The co-signer steps of lib.ps1 (phase_cosign, plan 20) assert on these two:
 *
 *   measure spawn-fed-hold <hook> <agent> <payload file> <pid file> <wait seconds>
 *       Starts the hook with the payload file on its stdin and closes stdin, writes the
 *       hook's pid and a newline to <pid file>, then waits up to <wait> s for the hook to
 *       end and prints child_exit (259 is still running) as spawn-hold does. The hook
 *       inherits this process's environment, so SAIIFE_EVAL_FAULT reaches its worker.
 *   measure terminate-bound <pid file> <exit code> <max seconds>
 *       Waits for <pid file>, then for the hook's guard worker (a saiife.exe whose parent
 *       is that pid): the hook spawns it and then binds its key with the daemon. After
 *       BIND_SETTLE_MS, TerminateProcess(hook, <exit code>). Prints worker_seen_ms and
 *       kill_at_filetime (UTC, 100 ns since 1601), or why it did not kill.
 *
 * Output: key=value lines.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "advapi32.lib")

/* From the worker's start to the kill: long enough for the hook's hook.bind round trip,
 * well inside the hook's 3 s worker deadline. */
#define BIND_SETTLE_MS 300

static void say_err(const char *key) {
    printf("%s_error=%lu\n", key, GetLastError());
    fflush(stdout);
}

static void say_w(const char *key, const wchar_t *value) {
    printf("%s=%ls\n", key, value);
    fflush(stdout);
}

static void say_err_of(const char *key, const char *what) {
    printf("%s_%s_error=%lu\n", key, what, GetLastError());
    fflush(stdout);
}

/* A token's information `class`, in a buffer the caller frees; NULL on failure. */
static void *token_info(HANDLE token, TOKEN_INFORMATION_CLASS class) {
    DWORD len = 0;
    void *buf;
    GetTokenInformation(token, class, NULL, 0, &len);
    if (len == 0 || (buf = malloc(len)) == NULL) {
        return NULL;
    }
    if (!GetTokenInformation(token, class, buf, len, &len)) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* `<key>_user=<SID>` and one `<key>_group=<SID> <attributes> [logon]` line per group of
 * the token of `process`. Report-only: a failure is a `_error` line. */
static void say_token(const char *key, HANDLE process) {
    HANDLE token;
    TOKEN_USER *user;
    TOKEN_GROUPS *groups;
    wchar_t *text;
    DWORD i;

    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        say_err_of(key, "token");
        return;
    }
    user = (TOKEN_USER *)token_info(token, TokenUser);
    if (user == NULL) {
        say_err_of(key, "token_user");
    } else {
        if (ConvertSidToStringSidW(user->User.Sid, &text)) {
            printf("%s_user=%ls\n", key, text);
            LocalFree(text);
        }
        free(user);
    }
    groups = (TOKEN_GROUPS *)token_info(token, TokenGroups);
    if (groups == NULL) {
        say_err_of(key, "token_groups");
    } else {
        for (i = 0; i < groups->GroupCount; i++) {
            DWORD a = groups->Groups[i].Attributes;
            if (ConvertSidToStringSidW(groups->Groups[i].Sid, &text)) {
                printf("%s_group=%ls 0x%lx%s\n", key, text, a,
                       (a & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID ? " logon" : "");
                LocalFree(text);
            }
        }
        free(groups);
    }
    fflush(stdout);
    CloseHandle(token);
}

/* `<key>_sddl=<owner, group, DACL and label of the process object>`, read here. */
static void say_sddl(const char *key, HANDLE process) {
    const SECURITY_INFORMATION info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                      DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    PSECURITY_DESCRIPTOR sd = NULL;
    wchar_t *text = NULL;
    DWORD e = GetSecurityInfo(process, SE_KERNEL_OBJECT, info, NULL, NULL, NULL, NULL, &sd);

    if (e != ERROR_SUCCESS) {
        printf("%s_sddl_error=%lu\n", key, e);
        fflush(stdout);
        return;
    }
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, info, &text, NULL)) {
        printf("%s_sddl=%ls\n", key, text);
        LocalFree(text);
    } else {
        say_err_of(key, "sddl_text");
    }
    fflush(stdout);
    LocalFree(sd);
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
    /* Before the pid is out, so the killer cannot end the hook first. */
    say_token("hook", pi.hProcess);
    say_sddl("hook", pi.hProcess);
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
    HANDLE p, seen;

    say_token("killer", GetCurrentProcess());
    seen = OpenProcess(READ_CONTROL, FALSE, pid);
    if (seen == NULL) {
        say_err("target_read_control");
    } else {
        say_sddl("target", seen);
        CloseHandle(seen);
    }
    p = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
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

/* Starts the hook with the payload in `payload_path` on stdin, then closes stdin. */
static int spawn_fed_hold(const wchar_t *hook, const wchar_t *agent, const wchar_t *payload_path,
                          const wchar_t *pid_file, int wait) {
    static char payload[65536];
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE in_read, in_write, f;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t cmd[2048];
    DWORD len = 0, wrote = 0, code = 0;
    char text[32];
    int n;

    f = CreateFileW(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        say_err("payload_file");
        return 3;
    }
    if (!ReadFile(f, payload, (DWORD)sizeof payload, &len, NULL)) {
        say_err("payload_read");
        CloseHandle(f);
        return 3;
    }
    CloseHandle(f);
    if (len == 0 || len == (DWORD)sizeof payload) {
        printf("payload_error=size %lu\n", len);
        fflush(stdout);
        return 3;
    }
    if (!CreatePipe(&in_read, &in_write, &sa, 0)) {
        say_err("pipe");
        return 3;
    }
    SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_read;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    swprintf(cmd, 2048, L"\"%ls\" check --managed --hook-exit --agent %ls", hook, agent);
    if (!CreateProcessW(hook, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        say_err("hook_create");
        return 3;
    }
    CloseHandle(in_read);
    /* After the start: a payload larger than the pipe's buffer waits for the hook to read. */
    if (!WriteFile(in_write, payload, len, &wrote, NULL) || wrote != len) {
        say_err("payload_write");
    }
    CloseHandle(in_write);
    printf("payload_bytes=%lu\n", wrote);
    printf("hook_pid=%lu\n", pi.dwProcessId);
    fflush(stdout);
    /* The newline ends the pid: terminate-bound reads the file only once it has one. */
    f = CreateFileW(pid_file, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        say_err("pid_file");
        return 3;
    }
    n = sprintf(text, "%lu\n", pi.dwProcessId);
    WriteFile(f, text, (DWORD)n, &wrote, NULL);
    CloseHandle(f);
    WaitForSingleObject(pi.hProcess, (DWORD)wait * 1000);
    GetExitCodeProcess(pi.hProcess, &code);
    printf("child_exit=%lu\n", code);
    fflush(stdout);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

/* The pid in `pid_file`, once it holds digits and a newline; 0 until then. */
static DWORD read_pid_file(const wchar_t *pid_file) {
    char buf[32];
    DWORD got = 0;
    HANDLE f = CreateFileW(pid_file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        return 0;
    }
    if (!ReadFile(f, buf, (DWORD)sizeof buf - 1, &got, NULL)) {
        got = 0;
    }
    CloseHandle(f);
    buf[got] = '\0';
    if (strchr(buf, '\n') == NULL) {
        return 0;
    }
    return (DWORD)strtoul(buf, NULL, 10);
}

/* Whether a saiife.exe whose parent is `parent` runs: the hook's guard worker. */
static int has_worker(DWORD parent) {
    PROCESSENTRY32W pe;
    int found = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ParentProcessID == parent && _wcsicmp(pe.szExeFile, L"saiife.exe") == 0) {
                found = 1;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static int terminate_bound(const wchar_t *pid_file, UINT exit_code, int max_seconds) {
    ULONGLONG start = GetTickCount64();
    ULONGLONG deadline = start + (ULONGLONG)max_seconds * 1000;
    ULARGE_INTEGER at;
    FILETIME ft;
    DWORD pid = 0;
    HANDLE p;

    while ((pid = read_pid_file(pid_file)) == 0) {
        if (GetTickCount64() > deadline) {
            printf("pid_file_error=timeout\n");
            fflush(stdout);
            return 0;
        }
        Sleep(10);
    }
    printf("target_pid=%lu\n", pid);
    p = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (p == NULL) {
        say_err("open_process");
        return 0;
    }
    for (;;) {
        if (WaitForSingleObject(p, 0) == WAIT_OBJECT_0) {
            printf("target_exited_first=1\n");
            fflush(stdout);
            CloseHandle(p);
            return 0;
        }
        if (has_worker(pid)) {
            break;
        }
        if (GetTickCount64() > deadline) {
            printf("worker_seen=timeout\n");
            fflush(stdout);
            CloseHandle(p);
            return 0;
        }
        Sleep(5);
    }
    printf("worker_seen_ms=%llu\n", GetTickCount64() - start);
    Sleep(BIND_SETTLE_MS);
    if (TerminateProcess(p, exit_code)) {
        GetSystemTimeAsFileTime(&ft);
        at.LowPart = ft.dwLowDateTime;
        at.HighPart = ft.dwHighDateTime;
        printf("terminate=succeeded\n");
        printf("kill_at_filetime=%llu\n", at.QuadPart);
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
    if (argc == 7 && wcscmp(argv[1], L"spawn-fed-hold") == 0) {
        return spawn_fed_hold(argv[2], argv[3], argv[4], argv[5], _wtoi(argv[6]));
    }
    if (argc == 5 && wcscmp(argv[1], L"terminate-bound") == 0) {
        return terminate_bound(argv[2], (UINT)_wtoi(argv[3]), _wtoi(argv[4]));
    }
    if (argc == 4 && wcscmp(argv[1], L"terminate") == 0) {
        return terminate((DWORD)_wtoi(argv[2]), (UINT)_wtoi(argv[3]));
    }
    fprintf(stderr, "usage: see measure.c\n");
    return 2;
}
