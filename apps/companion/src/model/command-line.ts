/**
 * An argument vector as a person types it at a stock shell's prompt.
 *
 * The page never types into a stock shell, so it shows the command for the person to type. Each
 * shell reads quotes its own way, and text quoted for another shell runs as something else in this
 * one, so the vector is quoted for the shell the session runs.
 *
 * Most shells write a word as it is when it holds only characters no shell treats as more than
 * themselves, and as one quoted string otherwise. PowerShell reads more as syntax (a leading `@`,
 * `-` or `$`, a comma, a bare number), so every word of its line is one quoted string. That line
 * is the one the shell integration installs when it launches the same vector, so a person who types
 * it runs what a launch would have run, with two limits that the page cannot see past. It does not
 * see which alias, function or cmdlet that shell finds before the program, so it shows the program
 * as named, where a launch writes the program's full path if something else would stand in for it.
 * And it does not see that the program is a batch file, which Windows runs through cmd.exe: a launch
 * builds no line for such a program when a word is empty, or ends in a backslash after white space,
 * or holds a character cmd.exe reads again, or when the program's own path holds `%` or `!`. The
 * line shown here is the one for the words as given.
 */

import type { ShellKind } from './pending'

/** Characters every other shell here reads as themselves. */
const PLAIN = /^[\w@%+=:,./-]+$/

/** The five characters PowerShell reads as a single quote: the ASCII one and four typographic ones. */
const POWERSHELL_QUOTES = /['\u2018\u2019\u201A\u201B]/g

/** One string of PowerShell: the word in single quotes, each quote character written twice. */
function powershellString(argument: string): string {
  return `'${argument.replace(POWERSHELL_QUOTES, '$&$&')}'`
}

/** One argument after the program, as a word of PowerShell. */
function powershellWord(argument: string): string {
  // Its stop-parsing token is left out of a program's arguments wherever it is written, quoted or
  // not, and the array expression is the one spelling that passes it on.
  return argument === '--%' ? "@('--%')" : powershellString(argument)
}

/** One argument as a single word of a shell other than PowerShell. */
function word(argument: string, kind: Exclude<ShellKind, 'powershell'>): string {
  // Zsh reads a word that starts with `=` as the path of a command, and Fish reads `%self` as a
  // process number, so neither is left bare.
  const bare = PLAIN.test(argument) && !argument.startsWith('=') && !argument.startsWith('%')
  if (bare) return argument
  if (kind === 'fish') return `'${argument.replaceAll('\\', '\\\\').replaceAll("'", "\\'")}'`
  return `'${argument.replaceAll("'", `'\\''`)}'`
}

/** The vector `argv` as one line for the shell `kind`. */
export function commandLine(argv: readonly string[], kind: ShellKind): string {
  if (kind === 'powershell') {
    if (argv.length === 0) return ''
    // A quoted word at the start of a line is a string to print, and the call operator is what
    // runs it, so the operator comes first and the program is quoted like the words after it.
    const [program, ...rest] = argv
    return ['&', powershellString(program), ...rest.map(powershellWord)].join(' ')
  }
  return argv.map((argument) => word(argument, kind)).join(' ')
}
