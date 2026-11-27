/**
 * Where a technical word may end a line.
 *
 * Each row is a word as the page shows it and the parts a line may end between. The parts joined
 * are the word, so that the break places add no character.
 */

import { describe, expect, it } from 'vitest'

import { breakParts } from '../src/model/technical-word'

const ROWS: ReadonlyArray<readonly [string, readonly string[]]> = [
  // An application identifier ends a line after each dot.
  ['com.kalareach.companion', ['com.', 'kalareach.', 'companion']],
  // A path ends a line after a slash; the slash and the dot that open a word stay with it.
  [
    '/Users/sam/.local/share/kalareach',
    ['/Users/', 'sam/', '.local/', 'share/', 'kalareach']
  ],
  ['C:\\Program Files\\KalaReach\\kr.exe', ['C:\\', 'Program Files\\', 'KalaReach\\', 'kr.', 'exe']],
  // An option keeps its hyphens: a line ends before a run of them, never after.
  ['"--inspect"', ['"--inspect"']],
  ['--cache-dir', ['--cache', '-dir']],
  ['--no-color=always', ['--no', '-color=', 'always']],
  // A host name, an address and a URL.
  ['reach.kala.to', ['reach.', 'kala.', 'to']],
  ['https://reach.kala.to/pair?code=1', ['https://', 'reach.', 'kala.', 'to/', 'pair?code=', '1']],
  ['fe80::1c2d:3e4f', ['fe80::', '1c2d:', '3e4f']],
  ['kr@reach.kala.to', ['kr@', 'reach.', 'kala.', 'to']],
  // Words with an underscore, and words that open with one.
  ['kr_worker_main', ['kr_', 'worker_', 'main']],
  ['__init__.py', ['__init__.py']],
  // A number is one word: no dot, comma or hyphen between two digits ends a line.
  ['192.168.0.1', ['192.168.0.1']],
  ['1.2.3-rc.1', ['1.2.3', '-rc.', '1']],
  ['2026-11-26', ['2026-11-26']],
  // A word with a space keeps the space as a place the engine already breaks at.
  ['two words', ['two words']],
  ['', []]
]

describe('breakParts', () => {
  for (const [word, parts] of ROWS) {
    it(`parts ${JSON.stringify(word)}`, () => {
      expect(breakParts(word)).toEqual(parts)
      expect(breakParts(word).join('')).toBe(word)
    })
  }
})
