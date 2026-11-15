/* One 32-bit system call through int $0x80, from a 64-bit program.
 *
 *   ia32 getpid   the control: a harmless call
 *   ia32 vsock    socket(AF_VSOCK, SOCK_STREAM, 0) through the 32-bit table (call 359)
 *
 * Prints "RESULT ia32 <call> <return value>". A negative value is an errno; a unit that
 * restricts the system call architectures to the native one is ended by SIGSYS before it prints.
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
#if defined(__x86_64__)
    long nr = 20, a = 0, b = 0, c = 0, r;
    const char *name = (argc > 1) ? argv[1] : "getpid";
    if (strcmp(name, "vsock") == 0) {
        nr = 359; /* socket, i386 */
        a = 40;   /* AF_VSOCK */
        b = 1;    /* SOCK_STREAM */
        c = 0;
    }
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(nr), "b"(a), "c"(b), "d"(c) : "memory");
    printf("RESULT ia32 %s %ld\n", name, r);
    return 0;
#else
    (void)argc;
    (void)argv;
    printf("RESULT ia32 na not-x86-64\n");
    return 0;
#endif
}
