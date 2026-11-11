// Whether a module is the file Node was started with, so that it runs as a command and not when
// another file imports it.
//
// Node gives a module the real path of its file, and `process.argv[1]` keeps the path the command was
// started by. With a symbolic link in that path (`/tmp` and `/var` are links on macOS) the two names
// differ, and a module that compared them as they were ran nothing and ended 0: a store run that
// started it by a checkout's logical path then skipped the step without an error. So the path the
// command was started by is resolved to its real path first.
import { realpathSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

/** True when the module whose `import.meta.url` is given is the file this process was started with. */
export function startedAs(moduleUrl) {
  const started = process.argv[1]
  return Boolean(started) && pathToFileURL(realpathSync(started)).href === moduleUrl
}
