#!/usr/bin/env node
/**
 * Prepares the package for `pnpm pack`.
 *
 * A consumer of a packed release gets three things this repository keeps outside the package
 * directory, so `pnpm pack` assembles them here first:
 *
 * - `types/`, the declarations, so a consumer reads this package's types rather than compiling its
 *   source under its own compiler settings;
 * - `fixtures/`, the cross-language vectors for the types and the codec this package publishes, so
 *   a consumer can hold the release to the same bytes the Rust implementation is held to without a
 *   checkout of this repository;
 * - `provenance.json`, which names the revision the release was packed from, so a consumer that
 *   pins a revision can check that the archive it holds is that revision rather than trusting a
 *   file name.
 *
 * All three are generated, so none of them is committed. Packing refuses a working tree with
 * uncommitted changes under the package or the fixtures it copies: a release named after a
 * revision has to be that revision.
 */

import { execFileSync } from 'node:child_process'
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageDirectory = dirname(dirname(fileURLToPath(import.meta.url)))
const repositoryRoot = join(packageDirectory, '..', '..')

/** The vector directories for the types and the codec this package publishes. */
const FIXTURES = ['accounts', 'cbor', 'crypto', 'pairing', 'protocol', 'push', 'service']

function git (...args) {
  return execFileSync('git', ['-C', repositoryRoot, ...args], { encoding: 'utf8' }).trim()
}

const tracked = ['packages/protocol', ...FIXTURES.map((area) => `fixtures/${area}`)]
const dirty = git('status', '--porcelain', '--untracked-files=all', '--', ...tracked)

if (dirty !== '') {
  process.stderr.write(
    'Packing was refused: the package or its fixtures have uncommitted changes.\n' +
      'A release names the revision it was packed from, so commit or discard these first:\n' +
      `${dirty}\n`
  )
  process.exit(1)
}

const revision = git('rev-parse', 'HEAD')

rmSync(join(packageDirectory, 'types'), { recursive: true, force: true })
rmSync(join(packageDirectory, 'fixtures'), { recursive: true, force: true })

const require = createRequire(import.meta.url)

execFileSync(process.execPath, [require.resolve('typescript/bin/tsc'), '--project', 'tsconfig.build.json'], {
  cwd: packageDirectory,
  stdio: 'inherit'
})

mkdirSync(join(packageDirectory, 'fixtures'), { recursive: true })

for (const area of FIXTURES) {
  cpSync(join(repositoryRoot, 'fixtures', area), join(packageDirectory, 'fixtures', area), {
    recursive: true
  })
}

const manifest = JSON.parse(readFileSync(join(packageDirectory, 'package.json'), 'utf8'))

writeFileSync(
  join(packageDirectory, 'provenance.json'),
  `${JSON.stringify(
    {
      package: manifest.name,
      version: manifest.version,
      core_commit: revision,
      fixtures: FIXTURES
    },
    null,
    2
  )}\n`
)

process.stdout.write(`packed ${manifest.name} ${manifest.version} from ${revision}\n`)
