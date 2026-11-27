/**
 * Where a technical word may end a line.
 *
 * Each row is a word as the page shows it and the parts a line may end between. The parts joined
 * are the word, so that the break places add no character.
 */

import { describe, expect, it } from 'vitest'

import { breakParts } from '../src/model/technical-word'

const ROWS: ReadonlyArray<readonly [string, readonly string[]]> = [
  // An internal dot ends a line before it where the part after it is short (four characters or fewer),
  // so that a familiar ending stays whole, and after it where that part is longer.
  ['com.kalareach.companion', ['com.', 'kalareach.', 'companion']],
  ['com.apple.Terminal', ['com.', 'apple.', 'Terminal']],
  ['Info.plist', ['Info.', 'plist']],
  ['KalaReach.app', ['KalaReach', '.app']],
  ['archive.tar.gz', ['archive', '.tar', '.gz']],
  ['x.kala.verylongname', ['x', '.kala.', 'verylongname']],
  // A path ends a line after a slash; the slash and the dot that open a word stay with it.
  [
    '/Users/sam/.local/share/kalareach',
    ['/Users/', 'sam/', '.local/', 'share/', 'kalareach']
  ],
  ['C:\\Program Files\\KalaReach\\kr.exe', ['C:\\', 'Program Files\\', 'KalaReach\\', 'kr', '.exe']],
  ['node_modules/@types/node', ['node_', 'modules/', '@types/', 'node']],
  // An option keeps its hyphens: a line ends before a run of them, never after.
  ['"--inspect"', ['"--inspect"']],
  ['--cache-dir', ['--cache', '-dir']],
  ['--no-color=always', ['--no', '-color=', 'always']],
  // An option with a negative value ends a line after the equals sign, before the sign.
  ['--offset=-1', ['--offset=', '-1']],
  // A host name, an address and a URL.
  ['reach.kala.to', ['reach', '.kala', '.to']],
  ['https://reach.kala.to/pair?code=1', ['https://', 'reach', '.kala', '.to/', 'pair?code=', '1']],
  ['fe80::1c2d:3e4f', ['fe80::', '1c2d:', '3e4f']],
  ['192.168.0.1:8080', ['192.168.0.1:', '8080']],
  ['[2001:db8::1]:443', ['[2001:', 'db8::', '1]:', '443']],
  ['kr@reach.kala.to', ['kr', '@reach', '.kala', '.to']],
  // Words with an underscore end a line after it; a run of them, and a name that opens with one, do not split.
  ['kr_worker_main', ['kr_', 'worker_', 'main']],
  ['__init__.py', ['__init__', '.py']],
  ['_private_name.txt', ['_private_', 'name', '.txt']],
  ['a__b', ['a__', 'b']],
  ['a._b', ['a', '._b']],
  // A dot after underscores follows the same rule whether the underscores open the word or close a part.
  ['_.py', ['_', '.py']],
  ['__.py', ['__', '.py']],
  ['_.config', ['_.', 'config']],
  ['main_.py', ['main_', '.py']],
  ['main_.config', ['main_.', 'config']],
  // An internal at sign ends a line before it when text, a closing quote or bracket, or another sign
  // stands before it; one that opens its word (after an opening quote or bracket, another at sign, a dot
  // or a hyphen) or closes it does not.
  ['"sam"@example.com', ['"sam"', '@example', '.com']],
  ['(sam)@example.com', ['(sam)', '@example', '.com']],
  ['sam!@example.com', ['sam!', '@example', '.com']],
  ['sam+tag@example.com', ['sam+tag', '@example', '.com']],
  ['_@host.io', ['_', '@host', '.io']],
  ['@types/node', ['@types/', 'node']],
  ['"@x"', ['"@x"']],
  ['(@x)', ['(@x)']],
  ['sam@', ['sam@']],
  ['a.@b', ['a.@b']],
  ['a-@b', ['a-@b']],
  // A quote closes or opens by the quotes of the word, followed from its start, and not by the character
  // before it: a bracket inside a quote does not make the closing quote an opening one, and an equals
  // sign before a quote does not make it a closing one.
  ['"a("@example.com', ['"a("', '@example', '.com']],
  ['--file="@name"', ['--file="@name"']],
  // A quote after a letter or a digit closes what it follows; one that follows a closing quote opens the next.
  ['sam"@example.com', ['sam"', '@example', '.com']],
  ['"a""@x"', ['"a""@x"']],
  // A quote of another kind inside a quote opens a quote of its own.
  ['"\'@x\'"', ['"\'@x\'"']],
  // A digit before a quote is text before it, as a letter is: the quote closes what it follows.
  ['1"@x', ['1"', '@x']],
  // A backtick is a quote like the other two: one that opens keeps the at sign after it, one that closes
  // lets the line end before the at sign.
  ['`@x`', ['`@x`']],
  ['`a(`@example.com', ['`a(`', '@example', '.com']],
  // A second quote right after a quote that closed opens a quote; it does not close the first one again.
  ['a""@x', ['a""@x']],
  // A run of separators of any kind is one place, after its last character.
  ['a//::==b', ['a//::==', 'b']],
  ['a..b', ['a..b']],
  ['a---b', ['a', '---b']],
  // After a run of slashes, colons or equals signs a dot, an at sign or a hyphen starts a part only when a
  // letter or a digit stands further on in the word, past the signs that follow it: no mark is left alone
  // at the end of a line. A path that goes up keeps its places.
  ['--input=-', ['--input=-']],
  ['a/@', ['a/@']],
  ['a/.', ['a/.']],
  ['../../x', ['../', '../', 'x']],
  // A dot that opens or closes a word, or that a digit follows, never starts or ends a part of its own.
  ['.local', ['.local']],
  ['name.', ['name.']],
  ['Done.', ['Done.']],
  ['host.example.', ['host.', 'example.']],
  ['log.2', ['log.2']],
  ['libfoo.so.1', ['libfoo', '.so.1']],
  // A number is one word: no dot, comma or hyphen between two digits ends a line.
  ['192.168.0.1', ['192.168.0.1']],
  ['1.2.3-rc.1', ['1.2.3', '-rc.1']],
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

// A word of any length is read in one pass, so a long one needs no bound. Each case is a plain run with
// its exact parts; it holds no time limit.
describe('breakParts on a long word', () => {
  const REPEATS = 20_000

  it('a quote and an at sign, repeated: the first quote opens, every later one closes', () => {
    const word = '"@a'.repeat(REPEATS)
    const parts = breakParts(word)
    expect(parts).toEqual(['"@a"', ...Array.from({ length: REPEATS - 2 }, () => '@a"'), '@a'])
    expect(parts.join('')).toBe(word)
  })

  it('a long run of underscores: one part, then the part after the run', () => {
    const run = '_'.repeat(REPEATS)
    const word = `a${run}b`
    const parts = breakParts(word)
    expect(parts).toEqual([`a${run}`, 'b'])
    expect(parts.join('')).toBe(word)
  })
})
