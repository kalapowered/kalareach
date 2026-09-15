import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { componentExports, packageContract, witVersion } from '../src/index.js'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const wit = readFileSync(join(packageRoot, 'wit', 'kalareach-plugin.wit'), 'utf8')

describe('the published WIT package', () => {
  it('declares its name and version', () => {
    expect(wit).toContain(`package ${packageContract.wit_package.name}@${witVersion};`)
    expect(wit).toContain(`world ${packageContract.wit_package.world} {`)
  })

  it('declares every export the contract table names', () => {
    for (const name of componentExports) {
      expect(wit).toContain(`${name}: func`)
    }
  })

  it('imports every host interface the contract table names', () => {
    for (const entry of packageContract.wit_package.imports) {
      expect(wit).toContain(`import ${entry.interface};`)
      expect(entry.purpose.length).toBeGreaterThan(0)
    }
  })

  it('documents the execution limits a component runs under', () => {
    for (const limit of ['64 MiB', '10 ms', '50 ms', '100 ms', '1 MiB']) {
      expect(wit).toContain(limit)
    }
  })
})
