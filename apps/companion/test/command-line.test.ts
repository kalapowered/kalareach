/**
 * The command a stock shell's launch button shows, written for the shell the session runs.
 *
 * The page types nothing into a stock shell, so the text is all a launch gives the person. Quotes
 * mean something different in each shell, and a command quoted for the wrong one runs as something
 * else, so the same argument vector reads differently in each.
 */

import { describe, expect, it } from 'vitest'

import powershellLines from '../../../fixtures/shells/powershell-launch-lines.json'
import { commandLine } from '../src/model/command-line'
import type { ShellKind } from '../src/model/pending'

/** Every shell that quotes like a POSIX shell does. */
const POSIX: readonly ShellKind[] = ['sh', 'zsh', 'bash']

describe('a command written for the shell that reads it', () => {
  it('leaves a command made only of plain words as it is, in every shell that reads one so', () => {
    for (const kind of ['sh', 'zsh', 'bash', 'fish'] as const) {
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

  // PowerShell's line is the one the shell integration installs for a launch, word for word: the
  // call operator, then every word as one quoted string, and the one word PowerShell reads as its
  // stop-parsing token in the form that passes it on. The vectors are the ones the module's own
  // line is checked against in a real PowerShell.
  it.each(powershellLines.cases)('writes the line the shell integration installs: $name', (row) => {
    expect(commandLine(row.vector, 'powershell')).toBe(row.line)
  })

  it('quotes a word Zsh reads as the path of a command and one Fish reads as a process number', () => {
    expect(commandLine(['show', '=ls'], 'zsh')).toBe("show '=ls'")
    expect(commandLine(['show', 'a=b', '50%'], 'zsh')).toBe('show a=b 50%')
    expect(commandLine(['show', '%self'], 'fish')).toBe("show '%self'")
  })

  it('leaves the words PowerShell would take for splatting, a list or its stop-parsing token as they are in the other shells', () => {
    for (const kind of ['sh', 'zsh', 'bash', 'fish'] as const) {
      expect(commandLine(['show', '@payload', 'a,b', '--%', '-a.b'], kind)).toBe(
        'show @payload a,b --% -a.b'
      )
    }
  })
})
