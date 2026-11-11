// Whether a module is the file Node was started with, so that it runs as a command and not when
// another file imports it.
//
// Node names a module by a path, and `process.argv[1]` keeps the path the command was started by.
// With a symbolic link in that path (`/tmp` and `/var` are links on macOS) the two can differ: Node
// names the module by its real path, unless it is run with `--preserve-symlinks-main`, which keeps the
// link in the module's name and leaves the started path as it was. A module that compared the two as
// they were ran nothing and ended 0 in one case or the other: a store run that started it by a
// checkout's logical path then skipped the step without an error. So both sides are resolved to real
// paths before they are compared, which holds with the flag, without it, and when `NODE_OPTIONS`
// gives it.
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

/**
 * True when the module whose `import.meta.url` is given is the file this process was started with.
 *
 * A process with no entry file is started by no module: a program given with `-e` has no path, and one
 * read from standard input has the path `-`. Both answer false, so that importing a command file there
 * is no error. A path that names no file is an error and is not answered false, since a command that was
 * started by it would then do nothing and end 0.
 */
export function startedAs(moduleUrl) {
  const started = process.argv[1]
  if (!started || started === '-') return false
  return realpathSync(started) === realpathSync(fileURLToPath(moduleUrl))
}
