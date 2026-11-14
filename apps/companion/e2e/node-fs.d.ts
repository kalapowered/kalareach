/**
 * The file operations the stylesheet check reads the interface's sources with, and the ones the
 * evidence directory's reader and its cases resolve and make folders with.
 *
 * The browser tests are type-checked with the interface's own settings, which carry no Node types,
 * and bringing those in for one file would change the types every other file here is checked
 * against.
 */
declare module 'node:fs' {
  export function readFileSync(path: URL, encoding: 'utf8'): string
  export function readdirSync(path: URL, options: { recursive: true }): string[]
  export function existsSync(path: string): boolean
  export function mkdirSync(path: string, options: { recursive: true }): void
  export function mkdtempSync(prefix: string): string
  export function rmSync(path: string, options: { recursive: true; force: true }): void
  export function symlinkSync(target: string, path: string): void
  export const realpathSync: {
    (path: string): string
    native(path: string): string
  }
}
