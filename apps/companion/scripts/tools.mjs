// Where a development tool's own JavaScript entry is.
//
// The `node_modules/.bin` shims are shell scripts on Unix and command files on Windows, and a
// command file cannot be executed without an interpreter. A package's own entry is JavaScript on
// every platform, so that is what these scripts run, through this Node.
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'

const require = createRequire(import.meta.url)

/** The absolute path of one package's executable entry. */
export function toolPath(packageName) {
  const manifestPath = require.resolve(`${packageName}/package.json`)
  const manifest = require(manifestPath)
  const bin = typeof manifest.bin === 'string' ? manifest.bin : Object.values(manifest.bin ?? {})[0]
  if (!bin) throw new Error(`${packageName} has no executable entry`)
  return join(dirname(manifestPath), bin)
}
