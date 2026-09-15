#!/usr/bin/env node
/**
 * Generates src/generated/protocol.ts from schema/kalareach-protocol.schema.json.
 *
 *   node scripts/generate-types.mjs           write the file
 *   node scripts/generate-types.mjs --check   fail when the committed file differs
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { compile } from 'json-schema-to-typescript'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const schemaPath = join(packageRoot, 'schema', 'kalareach-protocol.schema.json')
const outputPath = join(packageRoot, 'src', 'generated', 'protocol.ts')

const banner = `/* eslint-disable */
/**
 * Generated from schema/kalareach-protocol.schema.json. Do not edit.
 *
 * Rust is canonical: change the types in crates/kr-protocol, run
 * \`cargo run -p kr-protocol --bin kr-protocol-gen\`, then \`pnpm -C packages/protocol generate\`.
 */
`

const schema = JSON.parse(await readFile(schemaPath, 'utf8'))

const generated = await compile(schema, 'KalaReachProtocol', {
  bannerComment: banner,
  additionalProperties: false,
  declareExternallyReferenced: true,
  enableConstEnums: false,
  style: { semi: false, singleQuote: true, printWidth: 100 },
  unknownAny: true
})

const check = process.argv.includes('--check')
if (check) {
  let current
  try {
    current = await readFile(outputPath, 'utf8')
  } catch (error) {
    console.error(`${outputPath}: ${error.message}`)
    process.exit(1)
  }
  if (current !== generated) {
    console.error(`${outputPath} is out of date; run \`pnpm -C packages/protocol generate\``)
    process.exit(1)
  }
  console.log('generated types are up to date')
} else {
  await mkdir(dirname(outputPath), { recursive: true })
  await writeFile(outputPath, generated, 'utf8')
  console.log(`wrote ${outputPath}`)
}
