/**
 * The environment the browser tests read the ports this run serves the bundles on from and name
 * the evidence directory in, and the folder the evidence directory's cases make a root outside the
 * platform's own in.
 *
 * Declared here for the same reason as the file operations beside it: the browser tests are
 * type-checked with the interface's own settings, which carry no Node types.
 */
declare module 'node:process' {
  export const env: Record<string, string | undefined>
  export function cwd(): string
}
