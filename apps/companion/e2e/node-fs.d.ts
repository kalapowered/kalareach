/**
 * The two file operations the stylesheet check reads the interface's sources with.
 *
 * The browser tests are type-checked with the interface's own settings, which carry no Node types,
 * and bringing those in for one file would change the types every other file here is checked
 * against.
 */
declare module 'node:fs' {
  export function readFileSync(path: URL, encoding: 'utf8'): string
  export function readdirSync(path: URL, options: { recursive: true }): string[]
}
