/**
 * The path operations the evidence directory's reader compares folders with.
 *
 * Declared here for the same reason as the file operations beside it: the browser tests are
 * type-checked with the interface's own settings, which carry no Node types.
 */
declare module 'node:path' {
  export const sep: string
  export function basename(path: string): string
  export function dirname(path: string): string
  export function isAbsolute(path: string): boolean
  export function join(...paths: string[]): string
  export function relative(from: string, to: string): string
}
