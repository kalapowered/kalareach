import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

/** The repository's shared fixture directory, which Rust and TypeScript both read. */
export const fixturesRoot = join(packageRoot, '..', '..', 'fixtures', 'plugins')

/** Returns the directory names under one fixture group, sorted. */
export function fixtureNames(group: 'valid' | 'invalid'): string[] {
  return readdirSync(join(fixturesRoot, group), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
}

/** Reads and parses one JSON file from a fixture package. */
export function readJson(...segments: string[]): unknown {
  return JSON.parse(readFileSync(join(fixturesRoot, ...segments), 'utf8'))
}

/** Reads one JSON file if it is present, otherwise returns undefined. */
export function readJsonIfPresent(...segments: string[]): unknown {
  try {
    return readJson(...segments)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
}
