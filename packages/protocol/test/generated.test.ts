import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

describe('generated types', () => {
  it('match the committed JSON Schema', () => {
    expect(() =>
      execFileSync(process.execPath, [join(packageRoot, 'scripts', 'generate-types.mjs'), '--check'], {
        cwd: packageRoot,
        stdio: 'pipe'
      })
    ).not.toThrowError()
  })

  it('cover the root messages the schema declares', () => {
    const schema = JSON.parse(
      readFileSync(join(packageRoot, 'schema', 'kalareach-protocol.schema.json'), 'utf8')
    ) as { properties: Record<string, unknown>, $defs: Record<string, unknown> }
    const generated = readFileSync(join(packageRoot, 'src', 'generated', 'protocol.ts'), 'utf8')
    for (const name of ['MutationRequest', 'Receipt', 'Grant', 'ProtocolError', 'MethodEntry']) {
      expect(generated).toContain(`export interface ${name} {`)
      expect(schema.$defs).toHaveProperty(name)
    }
    expect(Object.keys(schema.properties)).toContain('mutation_request')
  })

  it('declare the method and authority table as data', () => {
    const table = JSON.parse(
      readFileSync(join(packageRoot, 'schema', 'method-authority.json'), 'utf8')
    ) as { method_count: number, unlisted_methods_are_denied: boolean, methods: Array<{ name: string }> }
    expect(table.unlisted_methods_are_denied).toBe(true)
    expect(table.methods).toHaveLength(table.method_count)
    const names = table.methods.map((entry) => entry.name)
    expect(new Set(names).size).toBe(names.length)
    expect(names).toContain('agent.approval.respond')
    expect(names).not.toContain('host.shutdown')
  })
})

describe('identifier vocabulary', () => {
  it('exports a named type for every identifier the schema declares', () => {
    const schema = JSON.parse(
      readFileSync(join(packageRoot, 'schema', 'kalareach-protocol.schema.json'), 'utf8')
    ) as { properties: Record<string, { properties?: Record<string, { $ref?: string }> }> }
    const generated = readFileSync(join(packageRoot, 'src', 'generated', 'protocol.ts'), 'utf8')
    const vocabulary = schema.properties.identifiers?.properties ?? {}
    const names = Object.values(vocabulary)
      .map((entry) => entry.$ref?.replace('#/$defs/', ''))
      .filter((name): name is string => name !== undefined)
    expect(names.length).toBeGreaterThanOrEqual(55)
    const missing = names.filter(
      (name) => !new RegExp(`^export (type|interface) ${name}\\b`, 'm').test(generated)
    )
    expect(missing, `identifiers with no generated type: ${missing.join(', ')}`).toEqual([])
  })
})
