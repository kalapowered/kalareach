/**
 * The command a stock shell's launch button shows, written for the shell the session runs.
 *
 * The page types nothing into a stock shell, so the text is all a launch gives the person. Quotes
 * mean something different in each shell, and a command quoted for the wrong one runs as something
 * else, so the same argument vector reads differently in each.
 */

import { describe, expect, it } from 'vitest'

import { commandLine } from '../src/model/command-line'
import type { ShellKind } from '../src/model/pending'

/** Every shell that quotes like a POSIX shell does. */
const POSIX: readonly ShellKind[] = ['sh', 'zsh', 'bash']

describe('a command written for the shell that reads it', () => {
  it('leaves a command made only of plain words as it is, in every shell', () => {
    for (const kind of ['sh', 'zsh', 'bash', 'fish', 'powershell'] as const) {
      expect(commandLine(['pnpm', 'test', '--filter=app', './a/b.sh'], kind)).toBe(
        'pnpm test --filter=app ./a/b.sh'
      )
    }
  })

  it('quotes a word with a space or a quote the way a POSIX shell reads one', () => {
    for (const kind of POSIX) {
      expect(commandLine(['/Users/rs/My Notes/open', "it's", ''], kind)).toBe(
        `'/Users/rs/My Notes/open' 'it'\\''s' ''`
      )
    }
  })

  it('quotes a word with a backslash or a quote the way Fish reads one', () => {
    expect(commandLine(['/Users/rs/My Notes/open', "it's", 'a\\b'], 'fish')).toBe(
      `'/Users/rs/My Notes/open' 'it\\'s' 'a\\\\b'`
    )
  })

  it('doubles every quote PowerShell reads, and calls a program it had to quote', () => {
    // The ASCII quote and the four typographic ones all end a string in PowerShell.
    expect(commandLine(['C:\\Program Files\\Git\\git.exe', 'it\u2019s', "o'k", '\u2018\u201A\u201B'], 'powershell')).toBe(
      "& 'C:\\Program Files\\Git\\git.exe' 'it\u2019\u2019s' 'o''k' '\u2018\u2018\u201A\u201A\u201B\u201B'"
    )
    // A program that needed no quotes needs no call operator.
    expect(commandLine(['git', 'status'], 'powershell')).toBe('git status')
  })

  it('quotes a PowerShell word that starts with one dash and holds a dot, which it cuts at the dot', () => {
    for (const argument of ['-Dfoo.bar=baz', '-o.txt', '-a.b', '-v1.2']) {
      expect(commandLine(['show', argument], 'powershell')).toBe(`show '${argument}'`)
    }
    // A word with a colon waits for a value: none follows it at the end of a line, and the next
    // word or a dash inside it changes the arguments in the middle of one.
    for (const argument of ['-x:', '-a:b', '-a:--', '-a:-b:c', '-x:--%']) {
      expect(commandLine(['show', 'x', argument], 'powershell')).toBe(`show x '${argument}'`)
    }
    // A word with two dashes, or none, is whole as it is.
    expect(
      commandLine(['show', '--model=gpt-5.1', '--a.b', '--a:--', 'a:-b:c', 'a.b'], 'powershell')
    ).toBe('show --model=gpt-5.1 --a.b --a:-- a:-b:c a.b')
  })

  it('quotes a word Zsh reads as the path of a command and one Fish reads as a process number', () => {
    expect(commandLine(['show', '=ls'], 'zsh')).toBe("show '=ls'")
    expect(commandLine(['show', 'a=b', '50%'], 'zsh')).toBe('show a=b 50%')
    expect(commandLine(['show', '%self'], 'fish')).toBe("show '%self'")
  })

  it('quotes the words PowerShell would take for splatting or a list, which no other shell does', () => {
    expect(commandLine(['show', '@payload', 'a,b'], 'powershell')).toBe("show '@payload' 'a,b'")
    for (const kind of ['sh', 'zsh', 'bash', 'fish'] as const) {
      expect(commandLine(['show', '@payload', 'a,b'], kind)).toBe('show @payload a,b')
    }
  })

  it('writes the argument PowerShell reads as its stop-parsing token in the one form that keeps it', () => {
    expect(commandLine(['show', '--%', 'after'], 'powershell')).toBe("show @('--%') after")
    for (const kind of ['sh', 'zsh', 'bash', 'fish'] as const) {
      expect(commandLine(['show', '--%', 'after'], kind)).toBe('show --% after')
    }
  })
})
