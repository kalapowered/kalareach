/*
 * A native module of the person's own for the editor: it adds one widget and reads the editor's
 * line and cursor, which is what ties it to the reader it is loaded into.
 *
 * It is built several times against the headers of this repository's own Zsh package, as the person would
 * build one against the shell they run. Built as it stands it imports only what the package
 * provides. Built with KR_NEWER_IMPORT it also calls a function that no editor of this release
 * has, which is what a module built against a newer editor looks like from this side: it loads,
 * and the first call that needs the missing function ends the shell. Two more variants are the
 * controls: one imports from a package module that is not loaded yet, one imports a name it is
 * content to lose, and one calls the C library through pointers, so that it imports names the
 * library defines under a version.
 */

#include "zle.mdh"

#ifdef KR_NEWER_IMPORT
extern int zle_abi_newer_entry(void);
#endif

/* Names the editor provides only when a module of the package that is not loaded yet is loaded:
 * what a module of the person's imports from a package module they load later. */
#ifdef KR_LAZY_IMPORT
extern int asklist(void);
#endif

/* An import the module is content to lose. */
#ifdef KR_WEAK_IMPORT
# ifdef __APPLE__
extern int zle_abi_absent_but_optional(void) __attribute__((weak_import));
# else
extern int zle_abi_absent_but_optional(void) __attribute__((weak));
# endif
#endif

/* Names the C library versions on Linux: a call made through a pointer that the compiler cannot
 * fold leaves an undefined symbol that carries a version, which is what a module built on another
 * machine imports from the library of its own. */
#ifdef KR_VERSIONED_IMPORT
# include <string.h>
static void *(*volatile kr_copy)(void *, const void *, size_t) = memcpy;
static size_t (*volatile kr_measure)(const char *) = strlen;
#endif

/* Each variant names its own widget, so two of them can be loaded into one shell. */
#ifndef KR_WIDGET
# define KR_WIDGET "kr-user-abi"
#endif

static Widget kr_user_widget;

static int
kr_user_action(UNUSED(char **args))
{
#if defined(KR_VERSIONED_IMPORT)
    {
        char to[8];

        kr_copy(to, "kr", 3);
        return (int)kr_measure(to) + (zlecs > zlell);
    }
#elif defined(KR_NEWER_IMPORT)
    return zle_abi_newer_entry();
#elif defined(KR_LAZY_IMPORT)
    return asklist() + (zlecs > zlell);
#elif defined(KR_WEAK_IMPORT)
    return zle_abi_absent_but_optional != NULL ? zle_abi_absent_but_optional() : zlecs > zlell;
#else
    return zlecs > zlell;
#endif
}

static struct features module_features = { NULL, 0, NULL, 0, NULL, 0, NULL, 0, 0 };

int
setup_(UNUSED(Module m))
{
    return 0;
}

int
features_(Module m, char ***features)
{
    *features = featuresarray(m, &module_features);
    return 0;
}

int
enables_(Module m, int **enables)
{
    return handlefeatures(m, &module_features, enables);
}

int
boot_(UNUSED(Module m))
{
    kr_user_widget = addzlefunction(KR_WIDGET, kr_user_action, 0);
    return kr_user_widget ? 0 : -1;
}

int
cleanup_(Module m)
{
    if (kr_user_widget) {
        deletezlefunction(kr_user_widget);
    }
    return setfeatureenables(m, &module_features, NULL);
}

int
finish_(UNUSED(Module m))
{
    return 0;
}
