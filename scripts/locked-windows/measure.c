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
 * The co-signer steps of lib.ps1 (phase_cosign, plan 20) assert on this one:
 *
 *   measure terminate-bound <pid file> <exit code> <max seconds>
 *       Waits for <pid file> (a pid and a newline: claude-sim.ps1 -Mode kill writes it),
 *       then KILL_AFTER_MS for the hook to bind its key with the daemon, then
 *       TerminateProcess(hook, <exit code>). Prints waited_ms and kill_at_filetime (UTC,
 *       100 ns since 1601), or why it did not kill. Since plan 21 Claude Code's hook judges
 *       in its own process, so there is no guard worker to wait for; with
 *       SAIIFE_EVAL_FAULT=hang its judgment hangs, and the hook denies itself only at 3 s.
 *       (plan 20's spawn-fed-hold is gone: the hook must be a child of the process that
 *       sends the co-sign request, which claude-sim.ps1 is.)
 *
 * phase_forge (plan 21) reports this one and asserts nothing about it:
 *
 *   measure service-view <service pid> <target pid>
 *       Run elevated. Enables SeDebugPrivilege and prints what the runner reads of the
 *       target (as_admin_created, as_admin_session: the control) and the target's
 *       descriptor, then impersonates a copy of the service's own token and reads the same
 *       as the service would (as_service_created, as_service_session, or their _error).
 *       The co-signer's process tie rejects a reused parent pid, or an asker in another
 *       session, only where the service can read these (plan 21, Task 4).
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

/* From the hook's pid to its kill: long enough for its start, hello, hook.begin, stdin and
 * hook.bind (about 150 ms on these runners), well inside its 3 s judgment deadline. */
#define KILL_AFTER_MS 1000

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

static int terminate_bound(const wchar_t *pid_file, UINT exit_code, int max_seconds) {
    ULONGLONG start = GetTickCount64();
    ULONGLONG deadline = start + (ULONGLONG)max_seconds * 1000;
    ULONGLONG seen;
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
    seen = GetTickCount64();
    printf("target_pid=%lu\n", pid);
    p = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (p == NULL) {
        say_err("open_process");
        return 0;
    }
    if (WaitForSingleObject(p, KILL_AFTER_MS) == WAIT_OBJECT_0) {
        printf("target_exited_first=1\n");
        fflush(stdout);
        CloseHandle(p);
        return 0;
    }
    printf("waited_ms=%llu\n", GetTickCount64() - seen);
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

/* SeDebugPrivilege on for this process: nonzero when it took. */
static int enable_debug(void) {
    HANDLE t;
    TOKEN_PRIVILEGES tp;
    int ok;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) {
        return 0;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(t);
        return 0;
    }
    ok = AdjustTokenPrivileges(t, FALSE, &tp, sizeof tp, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(t);
    return ok;
}

/* `<key>_created` and `<key>_session` of `pid`, as far as this thread's token may read
 * them, the way crates/win/src/ffi/proc.rs reads them (PROCESS_QUERY_LIMITED_INFORMATION). */
static void say_view(const char *key, DWORD pid) {
    FILETIME c, e, k, u;
    DWORD session = 0;
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (p == NULL) {
        say_err_of(key, "created");
    } else {
        if (GetProcessTimes(p, &c, &e, &k, &u)) {
            printf("%s_created=%llu\n", key, ((ULONGLONG)c.dwHighDateTime << 32) | c.dwLowDateTime);
        } else {
            say_err_of(key, "created");
        }
        CloseHandle(p);
    }
    if (ProcessIdToSessionId(pid, &session)) {
        printf("%s_session=%lu\n", key, session);
    } else {
        say_err_of(key, "session");
    }
    fflush(stdout);
}

static int service_view(DWORD service_pid, DWORD target) {
    HANDLE sp, st, seen, dup = NULL;
    TOKEN_USER *user;
    wchar_t *text;

    printf("debug_privilege=%s\n", enable_debug() ? "enabled" : "not_enabled");
    say_view("as_admin", target);
    seen = OpenProcess(READ_CONTROL, FALSE, target);
    if (seen == NULL) {
        say_err("target_read_control");
    } else {
        say_sddl("target", seen);
        CloseHandle(seen);
    }
    sp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, service_pid);
    if (sp == NULL) {
        say_err("service_open");
        return 0;
    }
    if (!OpenProcessToken(sp, TOKEN_DUPLICATE | TOKEN_QUERY, &st)) {
        say_err("service_token");
        CloseHandle(sp);
        return 0;
    }
    CloseHandle(sp);
    user = (TOKEN_USER *)token_info(st, TokenUser);
    if (user != NULL) {
        if (ConvertSidToStringSidW(user->User.Sid, &text)) {
            printf("service_user=%ls\n", text);
            LocalFree(text);
        }
        free(user);
    }
    if (!DuplicateTokenEx(st, TOKEN_IMPERSONATE | TOKEN_QUERY, NULL, SecurityImpersonation, TokenImpersonation, &dup)) {
        say_err("service_duplicate");
        CloseHandle(st);
        return 0;
    }
    CloseHandle(st);
    if (!SetThreadToken(NULL, dup)) {
        say_err("service_impersonate");
        CloseHandle(dup);
        return 0;
    }
    say_view("as_service", target);
    RevertToSelf();
    CloseHandle(dup);
    printf("service_view=done\n");
    fflush(stdout);
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
    if (argc == 4 && wcscmp(argv[1], L"service-view") == 0) {
        return service_view((DWORD)_wtoi(argv[2]), (DWORD)_wtoi(argv[3]));
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
