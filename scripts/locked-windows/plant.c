/*
 * The DLL planting probe of scripts/locked-windows (A4, W28). CI only.
 *
 * Built several ways from this one file (lib.ps1, Build-Native):
 *
 *   cl /LD plant.c /Fe:saiife-plant-probe.dll
 *       A DLL whose DllMain appends the loading program's path to MARKER. It exports
 *       saiife_plant_probe and nothing else. lib.ps1 copies it under the name of every
 *       import of saiife.exe that is not an API set.
 *
 *   cl /DCONTROL plant.c /link saiife-plant-probe.lib
 *       A program that imports saiife_plant_probe. Linked without /DEPENDENTLOADFLAG it
 *       must write the marker with the DLL in its cwd or on PATH: proof that the DLL and
 *       the way the job delivers it work. Linked with /DEPENDENTLOADFLAG:0x800 it must
 *       fail to start (STATUS_DLL_NOT_FOUND) and write nothing: proof that the flag does
 *       its job on this runner.
 *
 *   cl /DFAKE_HOOK plant.c
 *       A stand-in for saiife.exe that says it ran and exits 0. The DefineDosDevice
 *       measurement puts it where a remapped C: would find the hook.
 *
 *   cl /DFAKE_CLAUDE plant.c
 *       A stand-in for Claude Code's claude.exe that prints a version and exits 0. The
 *       runner has no Claude Code; doctor's agent-version check, run as the agent, reads
 *       this one from the agent's %USERPROFILE%\.local\bin (phase_forge, forge_doctor).
 *
 * A real import of saiife.exe, planted, has none of the exports saiife.exe wants. The
 * loader would then fail the process (STATUS_ENTRYPOINT_NOT_FOUND) with no DllMain run,
 * so lib.ps1 checks the hook's exit code as well as the marker.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Fixed, not from the environment: the hook's worker gets a cleaned environment, and the
 * marker must catch the worker too. prepare_host makes this dir writable by Users. */
#define MARKER L"C:\\saiife-locked-ci\\markers\\plant.log"

#if defined(CONTROL)

__declspec(dllimport) int saiife_plant_probe(void);

int main(void) {
    return saiife_plant_probe() == 42 ? 0 : 1;
}

#elif defined(FAKE_HOOK)

int main(void) {
    static const char line[] = "fake-hook ran\r\n";
    DWORD n = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, sizeof line - 1, &n, NULL);
    return 0;
}

#elif defined(FAKE_CLAUDE)

int main(void) {
    static const char line[] = "9.9.9 (Claude Code)\r\n";
    DWORD n = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, sizeof line - 1, &n, NULL);
    return 0;
}

#else

__declspec(dllexport) int saiife_plant_probe(void) {
    return 42;
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved) {
    (void)self;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t image[1024];
        char line[3200];
        DWORD len = GetModuleFileNameW(NULL, image, 1024);
        int n = WideCharToMultiByte(CP_UTF8, 0, image, (int)len, line, sizeof line - 2, NULL, NULL);
        HANDLE f = CreateFileW(MARKER, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD wrote = 0;
            line[n] = '\r';
            line[n + 1] = '\n';
            WriteFile(f, line, (DWORD)n + 2, &wrote, NULL);
            CloseHandle(f);
        }
    }
    return TRUE;
}

#endif
