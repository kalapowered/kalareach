/**
 * The environment the browser tests read the ports this run serves the bundles on from.
 *
 * Declared here for the same reason as the file operations beside it: the browser tests are
 * type-checked with the interface's own settings, which carry no Node types.
 */
declare module 'node:process' {
  export const env: Readonly<Record<string, string | undefined>>
}
