/**
 * The description of the machine that the performance case records beside its readings.
 *
 * Declared here for the same reason as the file operations and the environment beside it: the
 * browser tests are type-checked with the interface's own settings, which carry no Node types.
 */
declare module 'node:os' {
  export function platform(): string
  export function release(): string
  export function arch(): string
  export function cpus(): ReadonlyArray<{ model: string }>
  export function totalmem(): number
}
