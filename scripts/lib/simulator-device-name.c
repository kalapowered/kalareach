// A library the iOS pairing run has the application on the simulator load, so that the phone appears under a
// name the run chose. The simulator shares the Mac's kernel, and the application takes its device name from the
// kernel's host name (sysctl kern.hostname), which on the simulator is the Mac's own name: a picture of the
// Hosts tab would show it. This library replaces that one answer, and every other call goes on to the system.
//
//   xcrun --sdk iphonesimulator clang -arch arm64 -target arm64-apple-ios17.0-simulator -dynamiclib \
//       -DKR_DEVICE_NAME='"Test phone"' -o simulator-device-name.dylib simulator-device-name.c
//
// The run loads it with DYLD_INSERT_LIBRARIES in the application's launch environment.

#include <errno.h>
#include <string.h>
#include <sys/sysctl.h>

#ifndef KR_DEVICE_NAME
#error "KR_DEVICE_NAME names the device: -DKR_DEVICE_NAME='\"Test phone\"'"
#endif

static int named_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen == 2 && name[0] == CTL_KERN && name[1] == KERN_HOSTNAME && newp == NULL && oldlenp != NULL) {
        const size_t size = sizeof(KR_DEVICE_NAME);  // the name and its end
        if (oldp == NULL) {
            *oldlenp = size;  // a call that asks how long the answer is
            return 0;
        }
        if (*oldlenp < size) {
            *oldlenp = size;
            errno = ENOMEM;
            return -1;
        }
        memcpy(oldp, KR_DEVICE_NAME, size);
        *oldlenp = size;
        return 0;
    }
    return sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

struct interposition {
    const void *replacement;
    const void *replacee;
};

__attribute__((used)) static const struct interposition interpositions[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)named_sysctl, (const void *)sysctl},
};
