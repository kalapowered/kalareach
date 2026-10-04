/*
 * The ZLE half of the KalaReach root-editor bridge.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to Zsh by the KalaReach reader patch set and is distributed under the Zsh
 * licence that governs the rest of the package; see shells/zsh/LICENSE.
 *
 * Everything the contract asks a package to prove about its reader is read from ZLE's own state
 * here, in one operation, at the instant the reader is asked: the invoking key sequence, the bytes
 * the terminal still holds, the keys pushed back ahead of it, the edit buffer and which reader is
 * running. That is the native equivalent of $KEYS, $PENDING and $KEYS_QUEUED_COUNT, and taking the
 * three together is what a fence rests on.
 */

/* The lookup of a loaded module's image is behind this on glibc. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

/* The loader's own headers come before the shell's, whose names they would otherwise meet. */
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#endif

#if defined(__linux__) && defined(__GLIBC__)
#include <elf.h>
#include <link.h>
#endif

#include "zle.mdh"

#include "kr_bridge.h"
#include "kr_bridge_zle.h"

#include <stdio.h>
#include <termios.h>

/*
 * The reader's own revisions.
 *
 * A prompt generation counts primary readers; a reader revision counts every reader, so a plugin
 * that restarts the reader inside one prompt is a different reader and an old fence is stale. The
 * buffer revision changes when the buffer's contents change, which is what a launch's expectation
 * is checked against.
 */
static unsigned long kr_prompt_generation;
static unsigned long kr_reader_revision;
static unsigned long kr_buffer_revision;
static unsigned long kr_buffer_hash;
static unsigned long kr_cwd_revision;
static char *kr_cwd_seen;
static int kr_inside_reader;

/* What the reader is in the middle of, for the exclusions and the cancellation report. */
static int kr_pending_quoted;
static int kr_pending_numeric;
static int kr_pending_paste_open;
static int kr_source_is_pushed_back;

/* A takeover's cancellation: requested inside the wait, consumed at the next boundary. */
static int kr_cancel_requested;
static int kr_cancel_consumed;

/* True only while the reader is waiting for another key, which is what makes a key sequence
 * partial. At a boundary `keybuf` holds the sequence that invoked the current operation, which is
 * $KEYS rather than anything the reader is still waiting for. */
static int kr_in_key_wait;

/* True while a complete key sequence has been selected and its binding has not run. The person
 * typed it, so it is theirs and it goes before anything the worker asks for. */
static int kr_key_selected;

/* Whether this wait has already reported the reader idle. */
static int kr_idle_reported;

/*
 * Reads the mailbox. The worker retries a withheld fence at the reader's next idle report and
 * drops one that arrives while its exchange is still open, so a reader that was told no fence was
 * published reports idle again however many reports it has already sent.
 */
static void
kr_zle_service(void)
{
    kr_bridge_service();
    if (kr_bridge_take_fence_retry()) {
        kr_idle_reported = 0;
    }
}

/* A launch this reader installed, so a revocation can take exactly that text back out. */
static int kr_installed_chars;

/* True from a line's acceptance until the next primary reader: its commands are running. */
static int kr_line_running;

/* What the command being started now runs as, held until the next command asks. */
static kr_resolution kr_resolution_now;

/* The variable a line's own commands present to `kr detach`. */
#define KR_DETACH_TOKEN_VARIABLE "KR_DETACH_TOKEN"

static unsigned long
kr_hash_line(void)
{
    unsigned long hash = 2166136261UL;
    int i;

    for (i = 0; i < zlell; i++) {
        unsigned long value = (unsigned long)zleline[i];
        hash ^= value & 0xffUL;
        hash *= 16777619UL;
        hash ^= (value >> 8) & 0xffUL;
        hash *= 16777619UL;
    }
    hash ^= (unsigned long)zlell;
    hash *= 16777619UL;
    return hash;
}

/* One revision per observed change of the buffer's contents, counted where it is read. */
static void
kr_track_buffer(void)
{
    unsigned long hash = kr_hash_line();

    if (hash != kr_buffer_hash) {
        kr_buffer_hash = hash;
        kr_buffer_revision++;
    }
}

static void
kr_track_cwd(void)
{
    if (pwd == NULL) {
        return;
    }
    if (kr_cwd_seen == NULL || strcmp(kr_cwd_seen, pwd) != 0) {
        zsfree(kr_cwd_seen);
        kr_cwd_seen = ztrdup(pwd);
        kr_cwd_revision++;
    }
}

static int
kr_reader_context(void)
{
    switch (zlecontext) {
    case ZLCON_LINE_CONT:
        return KR_CONTEXT_CONTINUATION;
    case ZLCON_VARED:
    case ZLCON_SELECT:
        return KR_CONTEXT_READ_BUILTIN;
    default:
        return KR_CONTEXT_PRIMARY;
    }
}

static int
kr_keymap(void)
{
    if (!invicmdmode()) {
        if (curkeymapname != NULL && strcmp(curkeymapname, "viins") == 0) {
            return KR_KEYMAP_VI_INSERT;
        }
        if (curkeymapname != NULL && strcmp(curkeymapname, "emacs") == 0) {
            return KR_KEYMAP_EMACS;
        }
        if (curkeymapname != NULL && strcmp(curkeymapname, "main") == 0) {
            return KR_KEYMAP_EMACS;
        }
        return KR_KEYMAP_CUSTOM;
    }
    return KR_KEYMAP_VI_COMMAND;
}

void
kr_shell_reader_state(kr_reader_state *out)
{
    size_t keys = (size_t)keybuflen;

    memset(out, 0, sizeof(*out));
    kr_track_buffer();
    /* A widget can change directory and return to the same prompt, so the revision is read where
     * it is reported rather than once at entry. */
    kr_track_cwd();

    out->prompt_generation = kr_prompt_generation;
    out->reader_revision = kr_reader_revision;
    out->reader_context = kr_reader_context();

    out->buffer_revision = kr_buffer_revision;
    out->buffer_empty = (zlell == 0);
    out->keymap = kr_keymap();

    out->pending_quoted_insertion = kr_pending_quoted;
    /* Keys pushed back by a widget or `zle -U` are the reader's own input, not the person's. */
    out->pending_macro_input = (kungetct > 0);
    /* ZLE keeps its own flag for an active incremental search. */
    out->pending_search = (isearch_active != 0);
    /* Being accumulated, or accumulated and waiting for the command it applies to. */
    out->pending_numeric_argument =
        kr_pending_numeric || prefixflag || (zmod.flags & (MOD_MULT | MOD_TMULT)) != 0;
    out->pending_multikey_sequence = (kr_in_key_wait && keybuflen > 0);
    out->pending_vi_motion = (virangeflag != 0);
    out->pending_paste = kr_pending_paste_open;

    if (keys > KR_KEYS_MAX) {
        keys = KR_KEYS_MAX;
    }
    memcpy(out->keys, keybuf, keys);
    out->keys_len = keys;
    out->pending_bytes = (unsigned long)noquery(0) + (kr_key_selected ? 1u : 0u);
    out->queued_keys = (unsigned long)kungetct;

    out->tty_typeahead_drained = (out->pending_bytes == 0);
    out->macro_input_drained = (kungetct == 0);
    out->partial_key_drained = !(kr_in_key_wait && keybuflen > 0);

    out->cwd_revision = kr_cwd_revision;
}

int
kr_shell_install_command(const char *text, size_t len)
{
    char *line;
    int metafied = 0;

    if (!zleactive || zlell != 0 || len == 0) {
        return 0;
    }
    if (zlemetaline != NULL) {
        unmetafy_line();
        metafied = 1;
    }
    /* The editor's own representation: `setline` unmetafies what it is given, so raw bytes above
     * 0x7f would change on the way in. */
    line = (char *)zalloc(len + 1);
    memcpy(line, text, len);
    line[len] = '\0';
    line = metafy(line, (int)len, META_REALLOC);
    setline(line, ZSL_TOEND);
    free(line);
    if (metafied) {
        metafy_line();
    }
    kr_installed_chars = zlell;
    kr_track_buffer();
    return zlell > 0;
}

int
kr_shell_remove_installed(void)
{
    int metafied = 0;

    if (kr_installed_chars <= 0) {
        return 0;
    }
    if (!zleactive) {
        kr_installed_chars = 0;
        return 0;
    }
    if (zlemetaline != NULL) {
        unmetafy_line();
        metafied = 1;
    }
    /* Only the text this launch installed comes out, and only while it is still all there. */
    if (zlell == kr_installed_chars) {
        zlecs = 0;
        foredel(zlell, CUT_RAW);
    }
    if (metafied) {
        metafy_line();
    }
    kr_installed_chars = 0;
    done = 0;
    kr_track_buffer();
    return 1;
}

void
kr_shell_accept_line(void)
{
    /* The read loop returns at its next boundary, which the patched zlecore takes immediately. */
    done = 1;
}

void
kr_shell_cancel_key_wait(kr_cancellation *out)
{
    out->partial_escape = (kr_in_key_wait && keybuflen > 0 && (unsigned char)keybuf[0] == 0x1b);
    out->multikey_sequence = (kr_in_key_wait && keybuflen > 0);
    out->quoted_insertion = kr_pending_quoted;
    out->vi_motion = (virangeflag != 0);
    out->macro_input = (kungetct > 0);
    out->buffer_preserved = 1;

    if (out->partial_escape || out->multikey_sequence || out->quoted_insertion || out->vi_motion ||
        out->macro_input) {
        out->discarded_bytes = (unsigned long)kungetct + (unsigned long)keybuflen;
        /* The old lease's undelivered input goes, the edit buffer stays. */
        kungetct = 0;
        /* The reader is inside something, so it is brought out of it: the wait ends and the
         * part-read sequence is dropped at the boundary that follows. */
        kr_cancel_requested = 1;
    } else {
        /*
         * Nothing was in progress, so there is nothing to unwind and nothing to throw away. The
         * reader stays in the wait it is in, and a sequence the person starts afterwards is not
         * taken for one this cancellation ended.
         */
        out->discarded_bytes = 0;
    }
}

char *
kr_shell_quote_argument(const char *argument)
{
    size_t len = strlen(argument);
    char *metafied;
    char *quoted;
    char *copy = NULL;
    int raw_len;

    metafied = (char *)zalloc(len + 1);
    memcpy(metafied, argument, len + 1);
    metafied = metafy(metafied, (int)len, META_REALLOC);

    pushheap();
    /*
     * Every argument is quoted, including the first. An argument vector is installed as literal
     * arguments, and a bare word at command position would be a reserved word, an assignment or
     * an alias rather than the name the caller asked to run.
     *
     * `quotestring` escapes for the inside of single quotes and leaves the quotes themselves to
     * its caller, so they are added here. Without them nothing would be quoted at all.
     */
    quoted = quotestring(metafied, QT_SINGLE);
    if (quoted != NULL) {
        size_t quoted_len = strlen(quoted);
        char *unmetafied = (char *)zalloc(quoted_len + 3);
        unmetafied[0] = '\'';
        memcpy(unmetafied + 1, quoted, quoted_len);
        unmetafied[quoted_len + 1] = '\'';
        unmetafied[quoted_len + 2] = '\0';
        raw_len = (int)quoted_len + 2;
        unmetafy(unmetafied, &raw_len);
        copy = (char *)malloc((size_t)raw_len + 1);
        if (copy != NULL) {
            memcpy(copy, unmetafied, (size_t)raw_len);
            copy[raw_len] = '\0';
        }
        zfree(unmetafied, quoted_len + 3);
    }
    popheap();
    free(metafied);
    return copy;
}

void
kr_shell_print_hint(const char *line)
{
    showmsg(line);
    /* The editor flushes its own output when it next refreshes the display. A hint printed while
     * the reader is waiting for a key has no next refresh to wait for, so it goes out now. */
    if (shout != NULL) {
        fflush(shout);
    }
}

int
kr_shell_veof(void)
{
#ifdef HAS_TIO
    struct ttyinfo info;

    if (SHTTY == -1) {
        return -1;
    }
    gettyinfo(&info);
# ifdef HAVE_TERMIOS_H
    if (info.tio.c_cc[VEOF] == VDISABLEVAL) {
        return -1;
    }
    return (int)(unsigned char)info.tio.c_cc[VEOF];
# else
    if (info.tio.c_cc[VEOF] == VDISABLEVAL) {
        return -1;
    }
    return (int)(unsigned char)info.tio.c_cc[VEOF];
# endif
#else
    return eofchar;
#endif
}

void
kr_shell_unexport(const char *name)
{
    /* The shell's own parameter goes with the environment entry, so a child inherits neither. */
    unsetparam((char *)name);
}

/* The name a module states its setup function under. Configure decides it: some platforms prefix
 * every symbol, and some cannot give two modules the same names for their entry points. */
static char *
kr_setup_symbol(const char *module_name)
{
    size_t room = strlen(module_name) * 2 + 16;
    char *symbol = malloc(room);
    char *q;
    const char *p;

    if (symbol == NULL) {
        return NULL;
    }
    q = symbol;
#ifdef DLSYM_NEEDS_UNDERSCORE
    *q++ = '_';
#endif
    memcpy(q, "setup_", 6);
    q += 6;
#ifndef DYNAMIC_NAME_CLASH_OK
    for (p = module_name; *p; p++) {
        if (*p == '/') {
            *q++ = 'Q';
            *q++ = 's';
        } else if (*p == '_') {
            *q++ = 'Q';
            *q++ = 'u';
        } else if (*p == 'Q') {
            *q++ = 'Q';
            *q++ = 'q';
        } else {
            *q++ = *p;
        }
    }
#else
    (void)p;
#endif
    *q = '\0';
    return symbol;
}

/* ---- the verdict on each module the shell holds -------------------------------------------- */

/*
 * A module is a shared object that binds to the reader by name, so a module built against another
 * editor is one whose imports this reader does not provide: a function it has never had or has
 * since renamed. The shell loads modules lazily, so such a module loads without complaint and fails
 * at the first call that needs the missing name, which is a shell that ends in the middle of a
 * command. The handshake is made when the editor is set up, which can be before a startup file has
 * run, so it may not see a module a startup file loads. When the user-facing hooks are reported
 * live, which is after the person's startup files, this reads the imports of every dynamic module
 * the shell holds, and the report says for each whether every name it imports is provided.
 *
 * What is judged is the image the loader mapped, never a file opened again by its name: the name
 * can be replaced or removed after the module loaded, and the file then found is not the code the
 * shell runs. The module's undefined symbols are read from the tables the loader itself bound it
 * with, which are in memory already, so no file is opened or read. What is asked is whether the
 * running shell, the modules already loaded or the module's own libraries provide each name, and
 * the loader's own lookup answers. That lookup can run the resolver function of a library that
 * defines an indirect function, and it takes the loader's lock. This is the loader's normal work,
 * the work a `dlopen` that binds every name at once does, and it runs in the shell's own thread.
 * The check waits on nothing outside the process: it reads no file, starts no process, uses no
 * network and sets no sleep or deadline. A name that carries a symbol version is asked for under
 * that version, in the shell's global scope and in the module's own libraries. Every
 * module is judged, the package's own among them: where a module sits says nothing about what it
 * is, and the package's own bind like any other.
 *
 * What this does not see: a module built against another layout of the same names, one that binds
 * every symbol it imports; a name a library the module loads for itself imports in its turn; and a
 * module the shell loads afterwards. A name that a package module not yet loaded provides is
 * refused: the shell loads a package module for its own features, never because another module
 * imports from it. A module image that does not read as one is reported as such and never as
 * a module that binds. The reader is made for the shared objects a linker makes: a table that is
 * not where the loader's own bookkeeping puts it is not read.
 */

typedef struct {
    void *handle;
    kr_imports_state state;
    char detail[256];
} kr_scan;

static void
kr_scan_not_read(kr_scan *scan, const char *why)
{
    if (scan->state != KR_IMPORTS_NOT_READ) {
        scan->state = KR_IMPORTS_NOT_READ;
        snprintf(scan->detail, sizeof(scan->detail), "%s", why);
    }
}

/* The text a wire string carries: whatever is not well-formed UTF-8 becomes `?`. */
static void
kr_utf8_clean(char *text)
{
    unsigned char *p = (unsigned char *)text;

    while (*p != '\0') {
        size_t need = 0;

        if (*p < 0x80) {
            p++;
            continue;
        }
        if (*p >= 0xC2 && *p <= 0xDF) {
            need = 1;
        } else if (*p >= 0xE0 && *p <= 0xEF) {
            need = 2;
        } else if (*p >= 0xF0 && *p <= 0xF4) {
            need = 3;
        }
        if (need > 0) {
            size_t i;

            for (i = 1; i <= need && (p[i] & 0xC0) == 0x80; i++) {
            }
            /* The second byte narrows three lead bytes: no overlong form (E0, F0), no surrogate
             * (ED) and nothing above U+10FFFF (F4). */
            if (i == need + 1 && !(*p == 0xE0 && p[1] < 0xA0) && !(*p == 0xED && p[1] > 0x9F) &&
                !(*p == 0xF0 && p[1] < 0x90) && !(*p == 0xF4 && p[1] > 0x8F)) {
                p += need + 1;
                continue;
            }
        }
        *p++ = '?';
    }
}

/* Whether `handle`'s lookup finds `name`: a symbol whose value is zero is still one that exists.
 * The loader's lookup can run an indirect function's resolver, which is its normal work. */
static int
kr_provides(void *handle, const char *name)
{
    (void)dlerror();
    return dlsym(handle, name) != NULL || dlerror() == NULL;
}

#if defined(__linux__) && defined(__GLIBC__)
/* The same for one symbol under one version. */
static int
kr_provides_version(void *handle, const char *name, const char *version)
{
    (void)dlerror();
    return dlvsym(handle, name, version) != NULL || dlerror() == NULL;
}
#endif

/* Records `name` when nothing that can provide it does. */
static void
kr_check_import(const char *name, kr_scan *scan)
{
    if (scan->state != KR_IMPORTS_BOUND || name[0] == '\0') {
        return;
    }
    /* The shell and what it has loaded, then the module's own dependencies. */
    if (kr_provides(RTLD_DEFAULT, name) || kr_provides(scan->handle, name)) {
        return;
    }
    scan->state = KR_IMPORTS_MISSING;
    snprintf(scan->detail, sizeof(scan->detail), "%s", name);
    kr_utf8_clean(scan->detail);
}

#ifdef __APPLE__

/*
 * The undefined names of the Mach-O image the loader mapped at `header`. The symbol and string
 * tables are in the image's __LINKEDIT segment, which is mapped with it: a file offset in the load
 * commands is an address there, relative to where the segment's file offset puts it.
 */
static void
kr_module_imports(const void *header, void *handle, kr_scan *scan)
{
    const struct mach_header_64 *image = header;
    const unsigned char *cursor;
    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysymtab = NULL;
    const struct segment_command_64 *text = NULL;
    const struct segment_command_64 *linkedit = NULL;
    const unsigned char *base;
    uint32_t command;
    uint32_t used = 0;
    uint32_t index;

    (void)handle;
    if (image == NULL) {
        kr_scan_not_read(scan, "the loader does not say where it mapped it");
        return;
    }
    if (image->magic != MH_MAGIC_64 || (image->filetype != MH_BUNDLE && image->filetype != MH_DYLIB)) {
        kr_scan_not_read(scan, "its format is not one this reads");
        return;
    }
    cursor = (const unsigned char *)(image + 1);
    for (command = 0; command < image->ncmds; command++) {
        const struct load_command *load = (const struct load_command *)cursor;

        if (image->sizeofcmds < sizeof(*load) || used > image->sizeofcmds - sizeof(*load) ||
            load->cmdsize < sizeof(*load) || load->cmdsize > image->sizeofcmds - used) {
            kr_scan_not_read(scan, "its load commands run past their size");
            return;
        }
        if (load->cmd == LC_SEGMENT_64 && load->cmdsize >= sizeof(*text)) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)cursor;

            if (strncmp(segment->segname, "__TEXT", sizeof(segment->segname)) == 0) {
                text = segment;
            } else if (strncmp(segment->segname, "__LINKEDIT", sizeof(segment->segname)) == 0) {
                linkedit = segment;
            }
        } else if (load->cmd == LC_SYMTAB && load->cmdsize >= sizeof(*symtab)) {
            symtab = (const struct symtab_command *)cursor;
        } else if (load->cmd == LC_DYSYMTAB && load->cmdsize >= sizeof(*dysymtab)) {
            dysymtab = (const struct dysymtab_command *)cursor;
        }
        used += load->cmdsize;
        cursor += load->cmdsize;
    }
    if (text == NULL || linkedit == NULL || symtab == NULL || dysymtab == NULL ||
        linkedit->filesize > linkedit->vmsize) {
        kr_scan_not_read(scan, "its load commands name no symbol table this reads");
        return;
    }
    /* Where the loader put the segment that holds the tables, and what of it is theirs. */
    base = (const unsigned char *)((uintptr_t)image - (uintptr_t)text->vmaddr +
                                   (uintptr_t)linkedit->vmaddr) -
           (size_t)linkedit->fileoff;
    if (symtab->symoff < linkedit->fileoff ||
        symtab->symoff - linkedit->fileoff > linkedit->filesize ||
        symtab->nsyms > (linkedit->filesize - (symtab->symoff - linkedit->fileoff)) /
                            sizeof(struct nlist_64) ||
        symtab->stroff < linkedit->fileoff ||
        symtab->stroff - linkedit->fileoff > linkedit->filesize ||
        symtab->strsize > linkedit->filesize - (symtab->stroff - linkedit->fileoff) ||
        dysymtab->iundefsym > symtab->nsyms ||
        dysymtab->nundefsym > symtab->nsyms - dysymtab->iundefsym) {
        kr_scan_not_read(scan, "its symbol table is not one this reads");
        return;
    }
    for (index = dysymtab->iundefsym; index < dysymtab->iundefsym + dysymtab->nundefsym; index++) {
        const struct nlist_64 *symbol = (const struct nlist_64 *)(base + symtab->symoff) + index;
        const char *name;

        /* A weak reference is one the module is content to lose. */
        if ((symbol->n_type & N_TYPE) != N_UNDF || !(symbol->n_type & N_EXT) ||
            (symbol->n_desc & N_WEAK_REF)) {
            continue;
        }
        if (symbol->n_un.n_strx >= symtab->strsize) {
            kr_scan_not_read(scan, "its string table is not one this reads");
            return;
        }
        name = (const char *)(base + symtab->stroff) + symbol->n_un.n_strx;
        if (memchr(name, '\0', symtab->strsize - symbol->n_un.n_strx) == NULL) {
            kr_scan_not_read(scan, "its string table is not one this reads");
            return;
        }
        /* Every lazily bound image names the loader's binding routine, which the loader supplies
         * and which is the one name that carries no prefix. */
        if (strcmp(name, "dyld_stub_binder") == 0) {
            continue;
        }
        /* The loader's own lookup is made without the prefix the C compiler put on, and a name
         * that has none is one this does not know how to ask for. */
        if (name[0] != '_') {
            kr_scan_not_read(scan, "a name it imports is not one this knows how to ask for");
            return;
        }
        kr_check_import(name + 1, scan);
    }
}

#elif defined(__linux__) && defined(__GLIBC__)

/* The most entries a dynamic section is read to: a section that runs on is not one this reads. */
#define KR_DYNAMIC_MAX 4096u
/* The most symbols a module's symbol table is taken to hold. */
#define KR_SYMBOLS_MAX (1u << 24)
/* The most loadable segments of one object this keeps. */
#define KR_SEGMENTS_MAX 32

/* The memory the loader mapped for one object: where its loadable segments are. */
typedef struct {
    uintptr_t bias;
    const char *name;
    size_t count;
    uintptr_t start[KR_SEGMENTS_MAX];
    uintptr_t end[KR_SEGMENTS_MAX];
} kr_object;

static int
kr_collect_segments(struct dl_phdr_info *info, size_t size, void *data)
{
    kr_object *object = data;
    size_t i;

    (void)size;
    /* The object the loader calls this, at this bias: a bias alone does not name one. */
    if ((uintptr_t)info->dlpi_addr != object->bias || object->count != 0 ||
        strcmp(info->dlpi_name != NULL ? info->dlpi_name : "",
               object->name != NULL ? object->name : "") != 0) {
        return 0;
    }
    for (i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *segment = &info->dlpi_phdr[i];

        if (segment->p_type != PT_LOAD || !(segment->p_flags & PF_R)) {
            continue;
        }
        if (object->count == KR_SEGMENTS_MAX) {
            return 1;
        }
        object->start[object->count] = (uintptr_t)info->dlpi_addr + (uintptr_t)segment->p_vaddr;
        object->end[object->count] = object->start[object->count] + (uintptr_t)segment->p_memsz;
        object->count++;
    }
    return 1;
}

/* Whether the `size` bytes at `at` are inside one loadable segment of the object. */
static int
kr_mapped(const kr_object *object, const void *at, size_t size)
{
    uintptr_t from = (uintptr_t)at;
    size_t i;

    for (i = 0; i < object->count; i++) {
        if (from >= object->start[i] && from <= object->end[i] &&
            size <= object->end[i] - from) {
            return 1;
        }
    }
    return 0;
}

/*
 * An address the dynamic section holds. The loader may have added the load bias to it already,
 * which depends on the architecture, so the address is the one of the two that is in the object's
 * own memory. Where both or neither are, this is not an address it can tell, and the answer is 0.
 */
static uintptr_t
kr_dynamic_address(const kr_object *object, uintptr_t value)
{
    int as_given;
    int moved;

    if (object->bias == 0) {
        return kr_mapped(object, (const void *)value, 1) ? value : 0;
    }
    as_given = kr_mapped(object, (const void *)value, 1);
    moved = kr_mapped(object, (const void *)(value + object->bias), 1);
    if (as_given == moved) {
        return 0;
    }
    return as_given ? value : value + object->bias;
}

/* The name of the version the module's version table calls `index`, or NULL when it lists none. */
static const char *
kr_needed_version(const kr_object *object, const ElfW(Verneed) *needs, size_t count,
                  uint16_t index, const char *strings, size_t string_size)
{
    const unsigned char *at = (const unsigned char *)needs;
    size_t file;

    if (needs == NULL) {
        return NULL;
    }
    for (file = 0; file < count && file < KR_DYNAMIC_MAX; file++) {
        const ElfW(Verneed) *need;
        const unsigned char *aux_at;
        size_t aux;

        if (!kr_mapped(object, at, sizeof(*need))) {
            return NULL;
        }
        need = (const ElfW(Verneed) *)at;
        aux_at = at + need->vn_aux;
        for (aux = 0; aux < need->vn_cnt && aux < KR_DYNAMIC_MAX; aux++) {
            const ElfW(Vernaux) *aux_entry;

            if (!kr_mapped(object, aux_at, sizeof(*aux_entry))) {
                return NULL;
            }
            aux_entry = (const ElfW(Vernaux) *)aux_at;
            if (aux_entry->vna_other == index) {
                if (aux_entry->vna_name >= string_size ||
                    memchr(strings + aux_entry->vna_name, '\0',
                           string_size - aux_entry->vna_name) == NULL) {
                    return NULL;
                }
                return strings + aux_entry->vna_name;
            }
            if (aux_entry->vna_next == 0) {
                break;
            }
            aux_at += aux_entry->vna_next;
        }
        if (need->vn_next == 0) {
            break;
        }
        at += need->vn_next;
    }
    return NULL;
}

/*
 * How many symbols the object's symbol table holds, from the hash table the loader looks names up
 * in, or 0 when that table is not one this reads.
 */
static size_t
kr_symbol_count(const kr_object *object, const uint32_t *gnu, const uint32_t *sysv)
{
    if (gnu != NULL) {
        uint32_t buckets;
        uint32_t first_hashed;
        uint32_t bloom;
        const uint32_t *table;
        const uint32_t *chains;
        uint32_t last = 0;
        uint32_t i;

        if (!kr_mapped(object, gnu, 4 * sizeof(uint32_t))) {
            return 0;
        }
        buckets = gnu[0];
        first_hashed = gnu[1];
        bloom = gnu[2];
        table = (const uint32_t *)((const ElfW(Addr) *)(gnu + 4) + bloom);
        chains = table + buckets;
        if (!kr_mapped(object, gnu + 4, (size_t)bloom * sizeof(ElfW(Addr)) +
                                            (size_t)buckets * sizeof(uint32_t))) {
            return 0;
        }
        for (i = 0; i < buckets; i++) {
            if (table[i] > last) {
                last = table[i];
            }
        }
        if (last < first_hashed) {
            return first_hashed;
        }
        while (last - first_hashed < KR_SYMBOLS_MAX) {
            if (!kr_mapped(object, &chains[last - first_hashed], sizeof(uint32_t))) {
                return 0;
            }
            if (chains[last - first_hashed] & 1u) {
                return (size_t)last + 1;
            }
            last++;
        }
        return 0;
    }
    if (sysv != NULL && kr_mapped(object, sysv, 2 * sizeof(uint32_t))) {
        return sysv[1];
    }
    return 0;
}

/*
 * The undefined names of the ELF object the loader mapped for `handle`. The dynamic section, and the
 * symbol, string, version and hash tables it points to, are what the loader bound the module with,
 * and they are in memory: each is read only where the object's own loadable segments say memory is.
 */
static void
kr_module_imports(const void *header, void *handle, kr_scan *scan)
{
    struct link_map *map = NULL;
    kr_object object;
    const ElfW(Dyn) *entry;
    const ElfW(Sym) *symbols = NULL;
    const char *strings = NULL;
    size_t string_size = 0;
    const uint16_t *versions = NULL;
    const ElfW(Verneed) *needs = NULL;
    size_t need_count = 0;
    const uint32_t *sysv = NULL;
    const uint32_t *gnu = NULL;
    size_t symbol_size = sizeof(ElfW(Sym));
    size_t count;
    size_t seen = 0;
    size_t n;

    if (header == NULL || handle == NULL || dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 ||
        map == NULL || map->l_ld == NULL) {
        kr_scan_not_read(scan, "the loader does not say where it mapped it");
        return;
    }
    memset(&object, 0, sizeof(object));
    object.bias = (uintptr_t)map->l_addr;
    object.name = map->l_name;
    dl_iterate_phdr(kr_collect_segments, &object);
    if (object.count == 0) {
        kr_scan_not_read(scan, "the loader does not say which memory it mapped");
        return;
    }
    for (entry = map->l_ld;; entry++) {
        if (++seen > KR_DYNAMIC_MAX || !kr_mapped(&object, entry, sizeof(*entry))) {
            kr_scan_not_read(scan, "its dynamic section does not end where it is mapped");
            return;
        }
        if (entry->d_tag == DT_NULL) {
            break;
        }
        /* A tag that names a table and whose address cannot be placed is a table this cannot read:
         * it is never taken for a table that is not there. */
        switch (entry->d_tag) {
        case DT_SYMTAB:
        case DT_STRTAB:
        case DT_VERSYM:
        case DT_VERNEED:
        case DT_HASH:
        case DT_GNU_HASH:
            if (kr_dynamic_address(&object, entry->d_un.d_ptr) == 0) {
                kr_scan_not_read(scan, "a table address it holds is not one this can place");
                return;
            }
            break;
        default:
            break;
        }
        switch (entry->d_tag) {
        case DT_SYMTAB:
            symbols = (const ElfW(Sym) *)kr_dynamic_address(&object, entry->d_un.d_ptr);
            break;
        case DT_STRTAB:
            strings = (const char *)kr_dynamic_address(&object, entry->d_un.d_ptr);
            break;
        case DT_STRSZ:
            string_size = (size_t)entry->d_un.d_val;
            break;
        case DT_SYMENT:
            symbol_size = (size_t)entry->d_un.d_val;
            break;
        case DT_VERSYM:
            versions = (const uint16_t *)kr_dynamic_address(&object, entry->d_un.d_ptr);
            break;
        case DT_VERNEED:
            needs = (const ElfW(Verneed) *)kr_dynamic_address(&object, entry->d_un.d_ptr);
            break;
        case DT_VERNEEDNUM:
            need_count = (size_t)entry->d_un.d_val;
            break;
        case DT_HASH:
            sysv = (const uint32_t *)kr_dynamic_address(&object, entry->d_un.d_ptr);
            break;
        case DT_GNU_HASH:
            gnu = (const uint32_t *)kr_dynamic_address(&object, entry->d_un.d_ptr);
            break;
        default:
            break;
        }
    }
    if (symbols == NULL || strings == NULL || string_size == 0 || symbol_size != sizeof(*symbols)) {
        kr_scan_not_read(scan, "its dynamic section names no symbol table this reads");
        return;
    }
    count = kr_symbol_count(&object, gnu, sysv);
    if (count == 0 || count > KR_SYMBOLS_MAX) {
        kr_scan_not_read(scan, "its hash table is not one this reads");
        return;
    }
    if (!kr_mapped(&object, symbols, count * sizeof(*symbols)) ||
        !kr_mapped(&object, strings, string_size) ||
        (versions != NULL && !kr_mapped(&object, versions, count * sizeof(*versions)))) {
        kr_scan_not_read(scan, "its symbol tables are not where it is mapped");
        return;
    }
    for (n = 1; n < count; n++) {
        const char *name;

        if (symbols[n].st_shndx != SHN_UNDEF || ELF64_ST_BIND(symbols[n].st_info) == STB_WEAK ||
            ELF64_ST_TYPE(symbols[n].st_info) == STT_TLS) {
            continue;
        }
        if (symbols[n].st_name >= string_size) {
            kr_scan_not_read(scan, "its string table is not one this reads");
            return;
        }
        name = strings + symbols[n].st_name;
        if (memchr(name, '\0', string_size - symbols[n].st_name) == NULL) {
            kr_scan_not_read(scan, "its string table is not one this reads");
            return;
        }
        /* A name a version is required for comes from a library that defines versions: it is asked for
         * under that version, in the shell's global scope and in the module's own libraries. */
        if (versions != NULL && (versions[n] & 0x7fff) >= 2) {
            const char *version = kr_needed_version(&object, needs, need_count, versions[n] & 0x7fff,
                                                    strings, string_size);

            if (version == NULL) {
                kr_scan_not_read(scan, "a name it imports is bound to a version it does not list");
                return;
            }
            /* Once a name is missing the rest are not asked: each lookup can run a resolver. */
            if (scan->state == KR_IMPORTS_BOUND && !kr_provides_version(RTLD_DEFAULT, name, version) &&
                !kr_provides_version(handle, name, version)) {
                scan->state = KR_IMPORTS_MISSING;
                snprintf(scan->detail, sizeof(scan->detail), "%s@%s", name, version);
                kr_utf8_clean(scan->detail);
            }
            continue;
        }
        kr_check_import(name, scan);
    }
}

#else

static void
kr_module_imports(const void *header, void *handle, kr_scan *scan)
{
    (void)header;
    (void)handle;
    kr_scan_not_read(scan, "this platform's module format is not one this reads");
}

#endif

static void
kr_zle_free_partial(kr_module_report *reports, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        free(reports[i].name);
        free(reports[i].path);
    }
    free(reports);
}

static int
kr_zle_module_reports(kr_module_report **out, size_t *count)
{
    kr_module_report *list;
    size_t capacity = 0;
    size_t made = 0;
    int slot;

    *out = NULL;
    *count = 0;
    /* A shell with no module table is not one this can say anything of: the list is not made. */
    if (modulestab == NULL) {
        return 0;
    }
    for (slot = 0; slot < modulestab->hsize; slot++) {
        Module module;

        for (module = (Module)modulestab->nodes[slot]; module != NULL;
             module = (Module)module->node.next) {
            capacity++;
        }
    }
    list = calloc(capacity > 0 ? capacity : 1, sizeof(*list));
    if (list == NULL) {
        return 0;
    }
    for (slot = 0; slot < modulestab->hsize; slot++) {
        Module module;

        for (module = (Module)modulestab->nodes[slot]; module != NULL;
             module = (Module)module->node.next) {
            kr_module_report *report = &list[made];
            kr_scan scan;
            char *symbol;
            void *setup;
            Dl_info where;
            const void *header = NULL;

            /* An alias and a module linked into the shell have no file. */
            if ((module->node.flags & (MOD_ALIAS | MOD_LINKED)) || module->u.handle == NULL) {
                continue;
            }
            symbol = kr_setup_symbol(module->node.nam);
            setup = symbol != NULL ? dlsym(module->u.handle, symbol) : NULL;
            free(symbol);
            report->name = strdup(unmeta(module->node.nam));
            report->path = strdup("");
            if (report->name == NULL || report->path == NULL) {
                kr_zle_free_partial(list, made + 1);
                return 0;
            }
            /* The address of that function says which image the loader mapped the module in. */
            if (setup != NULL && dladdr(setup, &where) && where.dli_fname != NULL) {
                free(report->path);
                report->path = strdup(where.dli_fname);
                header = where.dli_fbase;
                if (report->path == NULL) {
                    kr_zle_free_partial(list, made + 1);
                    return 0;
                }
            }
#if defined(__linux__) && defined(__GLIBC__)
            /* The module's own file, which is what is judged, where a library it links is the one
             * that supplied the setup function the address above came from. */
            {
                struct link_map *own = NULL;

                if (dlinfo(module->u.handle, RTLD_DI_LINKMAP, &own) == 0 && own != NULL &&
                    own->l_name != NULL && own->l_name[0] != '\0') {
                    free(report->path);
                    report->path = strdup(own->l_name);
                    if (report->path == NULL) {
                        kr_zle_free_partial(list, made + 1);
                        return 0;
                    }
                }
            }
#endif
            memset(&scan, 0, sizeof(scan));
            scan.handle = module->u.handle;
            kr_module_imports(header, module->u.handle, &scan);
            kr_utf8_clean(report->name);
            kr_utf8_clean(report->path);
            report->state = scan.state;
            memcpy(report->detail, scan.detail, sizeof(report->detail));
            made++;
        }
    }
    *out = list;
    *count = made;
    return 1;
}

/*
 * Puts one variable in the shell's own exported environment.
 *
 * The line's own commands inherit it, and nothing started after the line has ended does: the
 * reader takes it out of the environment again at the next prompt.
 */
static void
kr_shell_export(const char *name, const char *value)
{
    unsetparam((char *)name);
    if (createparam((char *)name, PM_SCALAR | PM_EXPORTED) != NULL) {
        setsparam((char *)name, ztrdup_metafy(value));
    }
}

/* Whether the shell is running a command of the line itself: not one that a function, a sourced
 * or startup file, an eval, a trap, a hook or a widget runs. */
static int
kr_top_level(void)
{
    return zsh_eval_context != NULL && zsh_eval_context[0] != NULL &&
           strcmp(zsh_eval_context[0], "toplevel") == 0 && zsh_eval_context[1] == NULL;
}

/*
 * The executor's question in front of an external command it is about to fork: see the
 * `kr_resolve_hook` it calls. The words and the file are metafied; the answer is the bridge's own
 * until the next command asks.
 */
static int
kr_zle_resolve(char **argv, char *path, char ***launch, char ***environment)
{
    char **words;
    char *executable;
    char *cwd;
    char *found;
    int argc;
    int i;
    int launching;
    unsigned long revision;

    *launch = *environment = NULL;
    /*
     * A command of the line the person typed, started by the root shell itself at the top level. A
     * process forked from the root shell asks nothing and releases nothing: what the bridge holds
     * may be the launch that child is about to start, and the child can run a command of its own
     * first, as it does for STTY.
     */
    if (!kr_line_running || !kr_bridge_root_process() || !kr_top_level() || argv == NULL ||
        path == NULL || pwd == NULL) {
        return 0;
    }
    kr_bridge_resolution_free(&kr_resolution_now);
    for (argc = 0; argv[argc] != NULL; argc++) {
    }
    if (argc == 0) {
        return 0;
    }
    kr_track_cwd();
    revision = kr_cwd_revision;

    pushheap();
    words = (char **)zhalloc((size_t)(argc + 1) * sizeof(char *));
    for (i = 0; i < argc; i++) {
        words[i] = dupstring(argv[i]);
        unmetafy(words[i], NULL);
    }
    words[argc] = NULL;
    cwd = dupstring(pwd);
    unmetafy(cwd, NULL);
    found = dupstring(path);
    unmetafy(found, NULL);
    /* The file the search found, named absolutely: a relative directory on the path is the
     * working directory's. */
    if (found[0] == '/') {
        executable = found;
    } else {
        executable = (char *)zhalloc(strlen(cwd) + strlen(found) + 2);
        snprintf(executable, strlen(cwd) + strlen(found) + 2, "%s/%s", cwd, found);
    }
    launching = kr_bridge_resolve((const char *const *)words, (size_t)argc, executable, cwd,
                                  revision, kr_prompt_generation, &kr_resolution_now);
    popheap();
    if (launching) {
        *launch = kr_resolution_now.arguments;
        *environment = kr_resolution_now.environment;
    }
    return launching;
}

/*
 * A line of the shell was accepted and is about to run.
 *
 * Its command block starts, and the capability the worker minted for it goes into the exported
 * environment of the commands it runs, which is the only place `kr detach` looks for it.
 */
static void
kr_line_accepted(void)
{
    const char *token;
    char *line;
    char *cwd;
    int len = 0;

    kr_track_cwd();
    if (pwd != NULL) {
        pushheap();
        line = zlelineasstring(zleline, zlell, 0, &len, NULL, 1);
        unmetafy(line, &len);
        cwd = dupstring(pwd);
        unmetafy(cwd, NULL);
        kr_bridge_block_started(kr_prompt_generation, line, (size_t)len, cwd, kr_cwd_revision);
        popheap();
    }
    token = kr_bridge_line_token();
    if (token != NULL) {
        kr_shell_export(KR_DETACH_TOKEN_VARIABLE, token);
    } else {
        kr_shell_unexport(KR_DETACH_TOKEN_VARIABLE);
    }
    kr_line_running = 1;
}

/* ---- the reader's boundaries ------------------------------------------------------------------ */

void
kr_zle_setup(void)
{
    /* This shell loads native modules of its own, so its bridge lists them when the hooks go live. */
    kr_module_reports_hook = kr_zle_module_reports;
    kr_bridge_activate();
    /* Only the registered root shell asks; any other shell of this package pays nothing. */
    if (kr_bridge_registered()) {
        kr_resolve_hook = kr_zle_resolve;
    }
}

void
kr_zle_finish(void)
{
    kr_module_reports_hook = NULL;
    kr_resolve_hook = NULL;
    kr_bridge_resolution_free(&kr_resolution_now);
}

void
kr_zle_enter(void)
{
    /* The line before this prompt has run: its block ends with the shell's own status for it, and
     * its capability leaves the environment with it. That holds whether or not the bridge is still
     * there, because a capability the worker has ended must not outlive its line. */
    if (kr_line_running && zlecontext == ZLCON_LINE_START) {
        kr_line_running = 0;
        kr_bridge_block_finished(lastval);
        kr_shell_unexport(KR_DETACH_TOKEN_VARIABLE);
    }
    if (!kr_bridge_registered()) {
        return;
    }
    if (kr_inside_reader) {
        /* A reader starting inside another is a takeover: the one that was running is over. */
        kr_bridge_editor_leave(KR_LEAVE_READER_TAKEOVER);
    }
    kr_reader_revision++;
    if (zlecontext == ZLCON_LINE_START) {
        kr_prompt_generation++;
    }
    kr_track_cwd();
    kr_buffer_hash = kr_hash_line();
    kr_buffer_revision++;
    kr_installed_chars = 0;
    kr_pending_quoted = kr_pending_numeric = kr_pending_paste_open = 0;
    kr_cancel_requested = kr_cancel_consumed = kr_in_key_wait = 0;
    kr_key_selected = kr_idle_reported = 0;
    /* A reader that is starting is not inside anything a cancellation has to unwind. */
    kr_bridge_cancel_settled();
    kr_inside_reader = 1;
    kr_bridge_editor_enter();
}

void
kr_zle_leave(int eof_sent)
{
    int reason;

    if (!kr_bridge_registered() || !kr_inside_reader) {
        kr_inside_reader = 0;
        return;
    }
    if (eof_sent || exit_pending) {
        reason = KR_LEAVE_ROOT_EXIT;
    } else if (errflag) {
        reason = KR_LEAVE_CANCELLATION;
    } else if (done) {
        reason = KR_LEAVE_COMMAND_ACCEPTED;
    } else {
        reason = KR_LEAVE_CANCELLATION;
    }
    kr_inside_reader = 0;
    kr_installed_chars = 0;
    kr_cancel_requested = kr_cancel_consumed = 0;
    kr_bridge_cancel_settled();
    if (reason == KR_LEAVE_COMMAND_ACCEPTED) {
        /* The accepted line is reported from the reader, inside the fence, before the leave: a
         * record sent after it could only ever say that nothing could be established. */
        kr_bridge_command_accepted();
    }
    kr_bridge_editor_leave(reason);
    /* Input a running command read through the editor is not a line of the shell: the line that
     * started that command still owns the block and the capability. */
    if (reason == KR_LEAVE_COMMAND_ACCEPTED && kr_reader_context() != KR_CONTEXT_READ_BUILTIN) {
        kr_line_accepted();
    }
}

int
kr_zle_boundary(void)
{
    int source;
    int consumed;

    if (!kr_bridge_managed()) {
        return 0;
    }
    if (kr_cancel_consumed) {
        /* The takeover's cancellation ended the wait; the reader continues with its buffer. */
        kr_cancel_consumed = 0;
        keybuflen = 0;
        keybuf[0] = '\0';
        return 1;
    }
    /*
     * This is the key-sequence boundary: the reader has resolved one complete sequence and is
     * between operations, which is where its mailbox is read. The sequence it has resolved has
     * not run yet, so it is input of the person's that anything the mailbox holds waits behind.
     */
    kr_key_selected = 1;
    kr_zle_service();
    kr_key_selected = 0;
    if (done) {
        return 1;		/* a launch was installed and accepted */
    }
    source = kr_source_is_pushed_back ? KR_SOURCE_PUSHED_BACK
                                      : (kr_pending_paste_open ? KR_SOURCE_PASTE
                                                               : KR_SOURCE_TERMINAL);
    consumed = kr_bridge_pre_eof(lastchar, source) == KR_CONSUME;
    /* The next wait is a fresh chance to be idle. */
    kr_idle_reported = 0;
    return consumed;
}

void
kr_zle_before_wait(void)
{
    if (!kr_bridge_registered() || kr_idle_reported) {
        return;
    }
    if (keybuflen != 0 || kungetct != 0) {
        return;
    }
    /* Nothing buffered and nothing part-read, and the reader is about to wait: one of the three
     * points the worker retries a withheld fence at. */
    kr_idle_reported = 1;
    kr_in_key_wait = 1;
    kr_bridge_reader_idle();
    kr_in_key_wait = 0;
}

int
kr_zle_wait(void)
{
    if (!kr_bridge_registered()) {
        return 0;
    }
    /* Everything answered from here is answered by a reader that is waiting for another key. */
    kr_in_key_wait = 1;
    kr_zle_service();
    kr_in_key_wait = 0;
    if (kr_cancel_requested) {
        /* The wait is over, so the reader is out of whatever the cancellation ended and the
         * endpoint can be read again. */
        kr_cancel_requested = 0;
        kr_cancel_consumed = 1;
        kr_idle_reported = 0;
        kr_bridge_cancel_settled();
        return 1;
    }
    return done != 0;
}

int
kr_zle_fd(void)
{
    return kr_bridge_fd();
}

void
kr_zle_pass_end(void)
{
    /*
     * One pass of the read loop is over, so whatever a cancellation ended has ended: the reader is
     * back here, whether the wait returned or the binding ran. Anything that was waiting behind
     * the cancellation is read now, at this boundary, rather than at the next keystroke.
     */
    kr_cancel_requested = kr_cancel_consumed = 0;
    kr_bridge_cancel_settled();
    /* Whatever the pass did, the reader's queues may have changed, so the next wait reports
     * itself idle again and the worker gets its retry point. */
    kr_idle_reported = 0;
    kr_zle_service();
    /* Reading the endpoint there can itself have ended something, and at a pass boundary that has
     * ended too, so whatever came behind it is read now rather than at the next keystroke. */
    kr_cancel_requested = kr_cancel_consumed = 0;
    kr_bridge_cancel_settled();
    kr_zle_service();
}

void
kr_zle_source_pushed_back(void)
{
    kr_source_is_pushed_back = 1;
}

void
kr_zle_source_terminal(void)
{
    kr_source_is_pushed_back = 0;
}

void
kr_zle_pending_quoted_insertion(int active)
{
    kr_pending_quoted = active;
}

void
kr_zle_pending_numeric_argument(int active)
{
    kr_pending_numeric = active;
}

void
kr_zle_pending_paste(int active)
{
    kr_pending_paste_open = active;
}

/* ---- the guarded startup entry's one-shot activation -------------------------------------------- */

int
bin_kr_bridge(char *name, char **args, UNUSED(struct options *ops), UNUSED(int func))
{
    if (args[0] == NULL) {
        zwarnnam(name, "expected activated, lost or status");
        return 1;
    }
    if (strcmp(args[0], "status") == 0) {
        return kr_bridge_registered() ? 0 : 1;
    }
    if (strcmp(args[0], "activated") == 0) {
        if (!kr_bridge_registered()) {
            return 1;
        }
        kr_bridge_hooks_activated(kr_prompt_generation + 1);
        return 0;
    }
    if (strcmp(args[0], "lost") == 0) {
        int loss = KR_LOSS_SEMANTIC_HOOK_LOSS;

        const char *detail = "";
        if (args[1] != NULL) {
            if (strcmp(args[1], "post-startup-failure") == 0) {
                loss = KR_LOSS_POST_STARTUP_FAILURE;
            } else if (strcmp(args[1], "unqualified-root-replacement") == 0) {
                loss = KR_LOSS_UNQUALIFIED_ROOT_REPLACEMENT;
            }
            if (args[2] != NULL) {
                detail = args[2];
            }
        }
        kr_bridge_lost(loss, detail);
        return 0;
    }
    zwarnnam(name, "unknown request: %s", args[0]);
    return 1;
}
