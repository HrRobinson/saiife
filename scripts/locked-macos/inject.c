/*
 * The A4 probe of scripts/locked-macos (spec 9.2, plan 13 Task 12). CI only.
 *
 * Built two ways from this one file:
 *
 *   cc -dynamiclib -o inject.dylib inject.c
 *       A library whose constructor creates the file named by
 *       $SAIIFE_INJECT_MARKER. Loaded through DYLD_INSERT_LIBRARIES into
 *       the managed hook, it must never run: the hook binary is signed
 *       with the hardened runtime, so dyld ignores DYLD_* variables.
 *
 *   cc -DCONTROL -o inject-control inject.c
 *       A plain program with no constructor and no hardened runtime. With
 *       the library inserted the marker must appear: proof that the library
 *       and the way the job delivers the variable work. (A platform binary
 *       such as /usr/bin/env is no control: SIP strips DYLD_* there too.)
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef CONTROL

int main(void) {
    return 0;
}

#else

__attribute__((constructor)) static void saiife_ci_inject(void) {
    const char *path = getenv("SAIIFE_INJECT_MARKER");
    if (path == NULL || path[0] != '/') {
        return;
    }
    /* O_APPEND without O_EXCL: every process that loads the library adds
     * a line naming itself, so a failure shows whether the hook or one of
     * its children ran it. */
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0644);
    if (fd >= 0) {
        char line[256];
        int n = snprintf(line, sizeof line, "injected pid=%d ppid=%d prog=%s\n",
                         (int)getpid(), (int)getppid(), getprogname());
        if (n > 0) {
            (void)write(fd, line, (size_t)(n < (int)sizeof line ? n : (int)sizeof line - 1));
        }
        (void)close(fd);
    }
}

#endif
